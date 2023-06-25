use gadgets::util::{not, Expr};
use itertools::Itertools;

use crate::{
    witness::{into_casper_entities, CasperEntityRow, Committee, Validator},
    VALIDATOR0_GINDEX,
};

use super::*;

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
    pub is_attested: Column<Advice>,
    /// Type of field the row represents.
    pub field_tag: Column<Advice>,
    /// Index for FieldTag
    pub index: Column<Advice>,
    /// Generalized index for State tree Merkle proofs.
    pub gindex: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// SSZ chunk RLC
    pub ssz_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for ValidatorsTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.id.into(),
            self.tag.into(),
            self.is_active.into(),
            self.is_attested.into(),
            self.field_tag.into(),
            self.index.into(),
            self.gindex.into(),
            self.value.into(),
            self.ssz_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("id"),
            String::from("tag"),
            String::from("is_active"),
            String::from("is_attested"),
            String::from("field_tag"),
            String::from("index"),
            String::from("gindex"),
            String::from("value"),
            String::from("ssz_rlc"),
        ]
    }
}

impl ValidatorsTable {
    /// Construct a new [`ValidatorsTable`]
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
            tag: meta.advice_column(),
            is_active: meta.advice_column(),
            is_attested: meta.advice_column(),
            field_tag: meta.advice_column(),
            index: meta.advice_column(), // meta.advice_column_in(SecondPhase),
            gindex: meta.advice_column_in(SecondPhase),
            value: meta.advice_column_in(SecondPhase),
            ssz_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    pub fn assign_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &CasperEntityRow<Value<F>>,
    ) -> Result<(), Error> {
        // println!("assigning row.ssz_rlc: {:?}", row.ssz_rlc);
        for (column, value) in [
            (self.id, row.id),
            (self.tag, row.tag),
            (self.is_active, row.is_active),
            (self.is_attested, row.is_attested),
            (self.field_tag, row.field_tag),
            (self.index, row.index),
            (self.gindex, row.gindex),
            (self.value, row.value),
            (self.ssz_rlc, row.ssz_rlc),
        ] {
            region.assign_advice(
                || "assign state row on state table",
                column,
                offset,
                || value,
            )?;
        }
        Ok(())
    }

    /// Load the validators table into the circuit.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        committees: &[Committee],
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities(validators.iter(), committees.iter());

        layouter.assign_region(
            || "dev load state table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                for (offset, row) in casper_entities
                    .iter()
                    .flat_map(|e| e.table_assignment(challenge))
                    .enumerate()
                {
                    self.assign_with_region(&mut region, offset, &row)?;
                }

                Ok(())
            },
        )
    }

    pub fn queries<F: Field>(&self, meta: &mut VirtualCells<'_, F>) -> ValidatorTableQueries<F> {
        ValidatorTableQueries {
            id: meta.query_advice(self.id, Rotation::cur()),
            tag: meta.query_advice(self.tag, Rotation::cur()),
            is_active: meta.query_advice(self.is_active, Rotation::cur()),
            is_attested: meta.query_advice(self.is_attested, Rotation::cur()),
            // vitual queries for values
            balance: meta.query_advice(self.value, Rotation::cur()),
            slashed: meta.query_advice(self.value, Rotation::next()),
            activation_epoch: meta.query_advice(self.value, Rotation(2)),
            exit_epoch: meta.query_advice(self.value, Rotation(3)),
            // vitual queries for RLCs
            balance_rlc: meta.query_advice(self.ssz_rlc, Rotation::cur()),
            slashed_rlc: meta.query_advice(self.ssz_rlc, Rotation::next()),
            activation_epoch_rlc: meta.query_advice(self.ssz_rlc, Rotation(2)),
            exit_epoch_rlc: meta.query_advice(self.ssz_rlc, Rotation(3)),
            pubkey_lo_rlc: meta.query_advice(self.ssz_rlc, Rotation(4)),
            pubkey_hi_rlc: meta.query_advice(self.ssz_rlc, Rotation(5)),
        }
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        enable: Expression<F>,
        gindex: Expression<F>,
        value_rlc: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        vec![
            (
                gindex.clone() * enable.clone(),
                meta.query_advice(self.gindex, Rotation::cur()),
            ),
            (
                value_rlc.clone() * enable.clone(),
                meta.query_advice(self.ssz_rlc, Rotation::cur()),
            ), // TODO: should any other columns be included?
        ]
    }
}

#[derive(Clone)]
pub struct ValidatorTableQueries<F: Field> {
    pub id: Expression<F>,
    pub tag: Expression<F>,
    pub is_active: Expression<F>,
    pub is_attested: Expression<F>,
    /// Values
    pub balance: Expression<F>,
    pub activation_epoch: Expression<F>,
    pub exit_epoch: Expression<F>,
    pub slashed: Expression<F>,
    /// RLCs
    pub balance_rlc: Expression<F>,
    pub activation_epoch_rlc: Expression<F>,
    pub exit_epoch_rlc: Expression<F>,
    pub slashed_rlc: Expression<F>,
    pub pubkey_lo_rlc: Expression<F>,
    pub pubkey_hi_rlc: Expression<F>,
}

impl<F: Field> ValidatorTableQueries<F> {
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

    pub fn is_attested(&self) -> Expression<F> {
        self.is_attested.clone()
    }

    pub fn balance(&self) -> Expression<F> {
        self.balance.clone()
    }

    pub fn activation_epoch(&self) -> Expression<F> {
        self.activation_epoch.clone()
    }

    pub fn exit_epoch(&self) -> Expression<F> {
        self.exit_epoch.clone()
    }

    pub fn slashed(&self) -> Expression<F> {
        self.slashed.clone()
    }

    pub fn balance_rlc(&self) -> Expression<F> {
        self.balance_rlc.clone()
    }

    pub fn activation_epoch_rlc(&self) -> Expression<F> {
        self.activation_epoch_rlc.clone()
    }

    pub fn exit_epoch_rlc(&self) -> Expression<F> {
        self.exit_epoch_rlc.clone()
    }

    pub fn slashed_rlc(&self) -> Expression<F> {
        self.slashed_rlc.clone()
    }

    pub fn pubkey_lo_rlc(&self) -> Expression<F> {
        self.pubkey_lo_rlc.clone()
    }

    pub fn pubkey_hi_rlc(&self) -> Expression<F> {
        self.pubkey_hi_rlc.clone()
    }

    pub fn balance_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id())
            * 2u64.pow(3).expr() // 3 levels deeper
            + 2.expr() // skip pubkeyRoot and withdrawalCredentials
    }

    pub fn slashed_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 3.expr()
    }

    pub fn activation_epoch_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 5.expr() // skip activationEligibilityEpoch
    }

    pub fn exit_epoch_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(3).expr() + 6.expr()
    }

    pub fn pubkey_lo_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(4).expr() // 4 levels deeper
    }

    pub fn pubkey_hi_gindex(&self) -> Expression<F> {
        (VALIDATOR0_GINDEX.expr() + self.id()) * 2u64.pow(4).expr() + 1.expr()
    }
}
