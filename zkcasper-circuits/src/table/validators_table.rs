use std::marker::PhantomData;

use gadgets::util::{not, Expr};
use halo2_proofs::circuit::Cell;

use crate::witness::{into_casper_entities, CasperEntityRow, CasperTag, Committee, Validator};

use super::*;
use eth_types::Spec;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct ValidatorsTable {
    /// ValidatorIndex when tag == 'Validator', CommitteeIndex otherwise.
    pub id: Column<Advice>,
    /// Validator or Committee
    pub tag: Column<Advice>,
    /// Signals whether validator is active during that epoch.
    pub is_active: Column<Advice>,
    /// Signals whether validator have attested during that epoch.
    pub attest_bit: Column<Advice>,
    /// Effective balance of validator/committee.
    pub balance: Column<Advice>,
    /// Signals whether validator is slashed.
    pub slashed: Column<Advice>,
    /// Epoch when validator activated.
    pub activation_epoch: Column<Advice>,
    /// Epoch when validator exited.
    pub exit_epoch: Column<Advice>,
    /// Public key of a validator/committee.
    pub pubkey: [Column<Advice>; 2],
    /// Commitments to `is_attested` of validator per committee. Length = `Spec::attest_commits_len::<F>()`
    pub attest_commits: Vec<Column<Advice>>,
    /// Accumulated balance for *all* committees.
    pub total_balance_acc: Column<Advice>,

    pub pubkey_cells: Vec<[Cell; 2]>,
    pub attest_digits_cells: Vec<Vec<Cell>>,
}

impl<F: Field> LookupTable<F> for ValidatorsTable {
    fn columns(&self) -> Vec<Column<Any>> {
        itertools::chain!(
            vec![
                self.id.into(),
                self.tag.into(),
                self.is_active.into(),
                self.attest_bit.into(),
                self.balance.into(),
                self.slashed.into(),
                self.activation_epoch.into(),
                self.exit_epoch.into(),
                self.pubkey[0].into(),
                self.pubkey[1].into(),
                self.total_balance_acc.into(),
            ],
            self.attest_commits.iter().map(|c| (*c).into()),
        )
        .collect()
    }

    fn annotations(&self) -> Vec<String> {
        itertools::chain!(
            vec![
                String::from("id"),
                String::from("tag"),
                String::from("is_active"),
                String::from("is_attested"),
                String::from("balance"),
                String::from("slashed"),
                String::from("activation_epoch"),
                String::from("exit_epoch"),
                String::from("pubkey[0]"),
                String::from("pubkey[1]"),
                String::from("total_balance_acc"),
            ],
            (0..self.attest_commits.len()).map(|i| format!("attest_commits[{i}]")),
        )
        .collect()
    }
}

impl ValidatorsTable {
    /// Construct a new [`ValidatorsTable`]
    pub fn construct<S: Spec, F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let config = Self {
            id: meta.advice_column(),
            tag: meta.advice_column(),
            is_active: meta.advice_column(),
            attest_bit: meta.advice_column(),
            balance: meta.advice_column_in(SecondPhase),
            slashed: meta.advice_column_in(SecondPhase),
            activation_epoch: meta.advice_column_in(SecondPhase),
            exit_epoch: meta.advice_column_in(SecondPhase),
            pubkey: [
                meta.advice_column_in(SecondPhase),
                meta.advice_column_in(SecondPhase),
            ],
            attest_commits: (0..S::attest_digits_len::<F>())
                .map(|_| meta.advice_column())
                .collect(),
            total_balance_acc: meta.advice_column(),
            pubkey_cells: vec![],
            attest_digits_cells: vec![],
        };

        itertools::chain![&config.pubkey, &config.attest_commits,]
            .for_each(|&col| meta.enable_equality(col));

        config
    }

    pub fn assign_with_region<S: Spec, F: Field>(
        &mut self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &CasperEntityRow<F>,
    ) -> Result<(), Error> {
        let [attest_bit, pubkey_lo, pubkey_hi, ..] = [
            (self.attest_bit, row.is_attested),
            (self.pubkey[0], row.pubkey[0]),
            (self.pubkey[1], row.pubkey[1]),
            (self.id, row.id),
            (self.tag, row.tag),
            (self.is_active, row.is_active),
            (self.balance, row.balance),
            (self.slashed, row.slashed),
            (self.activation_epoch, row.activation_epoch),
            (self.exit_epoch, row.exit_epoch),
            (self.total_balance_acc, row.total_balance_acc),
        ]
        .map(|(column, value)| {
            region
                .assign_advice(
                    || "assign validator row into validators table",
                    column,
                    offset,
                    || value,
                )
                .expect("validator field assign")
                .cell()
        });

        let attest_commits_cells = self
            .attest_commits
            .iter()
            .zip(row.attest_commits.iter().copied())
            .map(|(column, value)| {
                region
                    .assign_advice(
                        || "assign attest commit into validators table",
                        *column,
                        offset,
                        || value,
                    )
                    .expect("attest commit assign")
                    .cell()
            })
            .collect();

        if row.row_type == CasperTag::Validator {
            self.pubkey_cells.push([pubkey_lo, pubkey_hi]);
            if (offset + 1) % S::MAX_VALIDATORS_PER_COMMITTEE == 0 {
                self.attest_digits_cells.push(attest_commits_cells);
            }
        }

        Ok(())
    }

    /// Load the validators table into the circuit.
    pub fn dev_load<S: Spec, F: Field>(
        &mut self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        committees: &[Committee],
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities::<S>(validators.iter(), committees.iter());

        layouter.assign_region(
            || "dev load validators table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                let mut committees_balances = vec![0; committees.len()];
                let mut attest_commits =
                    vec![vec![0; S::attest_digits_len::<F>()]; committees.len()];
                for (offset, row) in casper_entities
                    .iter()
                    .flat_map(|e| {
                        e.table_assignment::<S, F>(
                            challenge,
                            &mut attest_commits,
                            &mut committees_balances,
                        )
                    })
                    .enumerate()
                {
                    self.assign_with_region::<S, F>(&mut region, offset, &row)?;
                }

                Ok(())
            },
        )
    }

    pub fn queries<S: Spec, F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
    ) -> ValidatorTableQueries<S, F> {
        ValidatorTableQueries {
            id: meta.query_advice(self.id, Rotation::cur()),
            tag: meta.query_advice(self.tag, Rotation::cur()),
            is_active: meta.query_advice(self.is_active, Rotation::cur()),
            attest_bit: meta.query_advice(self.attest_bit, Rotation::cur()),
            balance: meta.query_advice(self.balance, Rotation::cur()),
            slashed: meta.query_advice(self.slashed, Rotation::cur()),
            activation_epoch: meta.query_advice(self.activation_epoch, Rotation::cur()),
            exit_epoch: meta.query_advice(self.exit_epoch, Rotation::cur()),
            pubkey_rlc: [
                meta.query_advice(self.pubkey[0], Rotation::cur()),
                meta.query_advice(self.pubkey[1], Rotation::cur()),
            ],
            balance_acc: meta.query_advice(self.total_balance_acc, Rotation::cur()),
            balance_acc_prev: meta.query_advice(self.total_balance_acc, Rotation::prev()),
            attest_commits: self
                .attest_commits
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect(),
            attest_commits_prev: self
                .attest_commits
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::prev()))
                .collect(),
            _spec: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct ValidatorTableQueries<S: Spec, F: Field> {
    id: Expression<F>,
    tag: Expression<F>,
    is_active: Expression<F>,
    attest_bit: Expression<F>,
    balance: Expression<F>,
    activation_epoch: Expression<F>,
    exit_epoch: Expression<F>,
    slashed: Expression<F>,
    pubkey_rlc: [Expression<F>; 2],
    balance_acc: Expression<F>,
    balance_acc_prev: Expression<F>,
    attest_commits: Vec<Expression<F>>,
    attest_commits_prev: Vec<Expression<F>>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field> ValidatorTableQueries<S, F> {
    pub fn is_validator(&self) -> Expression<F> {
        self.tag.clone()
    }

    pub fn is_committee(&self) -> Expression<F> {
        not::expr(self.tag.clone())
    }

    pub fn id(&self) -> Expression<F> {
        self.id.clone()
    }

    pub fn tag(&self) -> Expression<F> {
        self.tag.clone()
    }

    pub fn is_active(&self) -> Expression<F> {
        self.is_active.clone()
    }

    pub fn attest_bit(&self) -> Expression<F> {
        self.attest_bit.clone()
    }

    pub fn balance_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_G_INDEX.expr() + self.id())
            * 2u64.pow(3).expr() // 3 levels deeper
            + 2.expr() // skip pubkeyRoot and withdrawalCredentials
    }

    pub fn balance(&self) -> Expression<F> {
        self.balance.clone()
    }

    pub fn slashed(&self) -> Expression<F> {
        self.slashed.clone()
    }

    pub fn activation_epoch(&self) -> Expression<F> {
        self.activation_epoch.clone()
    }

    pub fn exit_epoch(&self) -> Expression<F> {
        self.exit_epoch.clone()
    }

    pub fn pubkey_lo_rlc(&self) -> Expression<F> {
        self.pubkey_rlc[0].clone()
    }

    pub fn pubkey_hi_rlc(&self) -> Expression<F> {
        self.pubkey_rlc[1].clone()
    }

    pub fn slashed_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_G_INDEX.expr() + self.id()) * 2u64.pow(3).expr() + 3.expr()
    }

    pub fn activation_epoch_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_G_INDEX.expr() + self.id()) * 2u64.pow(3).expr() + 5.expr()
        // skip activationEligibilityEpoch
    }

    pub fn exit_epoch_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_G_INDEX.expr() + self.id()) * 2u64.pow(3).expr() + 6.expr()
    }

    pub fn pubkey_lo_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_G_INDEX.expr() + self.id()) * 2u64.pow(4).expr() // 4 levels deeper 0 + 0 * 2^x = 94557999988736n
                                                                         // d = sqrt(94557999988736n) = 1048576 sqrt(86)
    }

    pub fn pubkey_hi_gindex(&self) -> Expression<F> {
        (S::VALIDATOR_0_G_INDEX.expr() + self.id()) * 2u64.pow(4).expr() + 1.expr()
    }

    pub fn balance_acc(&self) -> Expression<F> {
        self.balance_acc.clone()
    }

    pub fn balance_acc_prev(&self) -> Expression<F> {
        self.balance_acc_prev.clone()
    }

    pub fn attest_commit(&self, index: usize) -> Expression<F> {
        self.attest_commits[index].clone()
    }

    pub fn attest_commit_prev(&self, index: usize) -> Expression<F> {
        self.attest_commits_prev[index].clone()
    }
}
