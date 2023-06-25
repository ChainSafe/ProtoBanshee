pub(crate) mod cell_manager;
pub(crate) mod constraint_builder;

use crate::{
    gadget::LtGadget,
    table::{state_table::StateTables, LookupTable, ValidatorsTable},
    util::{Cell, Challenges, ConstrainBuilderCommon, SubCircuit, SubCircuitConfig},
    witness::{
        self, into_casper_entities, CasperEntity, CasperEntityRow, Committee, StateTag, Validator,
    },
    MAX_VALIDATORS, N_BYTES_U64, STATE_ROWS_PER_COMMITEE, STATE_ROWS_PER_VALIDATOR,
};
use cell_manager::CellManager;
use constraint_builder::*;
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::not,
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Any, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use lazy_static::lazy::Lazy;
use std::{iter, marker::PhantomData};

pub(crate) const N_BYTE_LOOKUPS: usize = 8;
pub(crate) const MAX_DEGREE: usize = 5;

#[derive(Clone, Debug)]
pub struct ValidatorsCircuitConfig<F: Field> {
    q_enabled: Column<Fixed>,
    is_validator: Column<Advice>,
    is_committee: Column<Advice>,
    state_tables: StateTables,
    pub validators_table: ValidatorsTable,
    storage_phase1: Column<Advice>,
    byte_lookup: [Column<Advice>; N_BYTE_LOOKUPS],
    target_epoch: Column<Advice>, // TODO: should be an instance or assigned from instance
    target_gte_activation: Option<LtGadget<F, N_BYTES_U64>>,
    target_lt_exit: Option<LtGadget<F, N_BYTES_U64>>,
    cell_manager: CellManager<F>,
}

pub struct ValidatorsCircuitArgs {
    pub state_tables: StateTables,
}

impl<F: Field> SubCircuitConfig<F> for ValidatorsCircuitConfig<F> {
    type ConfigArgs = ValidatorsCircuitArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let q_enabled = meta.fixed_column();
        let is_validator = meta.advice_column();
        let is_committee = meta.advice_column();
        let target_epoch = meta.advice_column();
        let state_tables = args.state_tables;
        let validators_table: ValidatorsTable = ValidatorsTable::construct(meta);

        let storage_phase1 = meta.advice_column_in(FirstPhase);
        let byte_lookup: [_; N_BYTE_LOOKUPS] = (0..N_BYTE_LOOKUPS)
            .map(|_| meta.advice_column_in(FirstPhase))
            .collect_vec()
            .try_into()
            .unwrap();

        let cm_advices = iter::once(storage_phase1)
            .chain(byte_lookup.iter().copied())
            .collect_vec();

        let cell_manager = CellManager::new(meta, MAX_VALIDATORS, &cm_advices);

        let mut config = Self {
            q_enabled,
            is_validator,
            is_committee,
            target_epoch,
            state_tables,
            validators_table,
            storage_phase1,
            byte_lookup,
            target_gte_activation: None,
            target_lt_exit: None,
            cell_manager,
        };

        // Annotate circuit
        config.validators_table.annotate_columns(meta);
        config.annotations().iter().for_each(|(col, ann)| {
            meta.annotate_lookup_any_column(*col, || ann);
        });

        meta.create_gate("validators constraints", |meta| {
            let q = queries(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);

            cb.require_boolean("tag in [validator/committee]", q.tag());
            cb.require_boolean("is_active is boolean", q.is_active());
            cb.require_boolean("is_attested is boolean", q.is_attested());
            cb.require_boolean("slashed is boolean", q.slashed());

            cb.condition(q.is_attested(), |cb| {
                cb.require_true("is_active is true when is_attested is true", q.is_active());
            });

            let target_gte_activation = LtGadget::<_, N_BYTES_U64>::construct(
                &mut cb,
                q.activation_epoch(),
                q.next_epoch(),
            );
            let target_lt_exit =
                LtGadget::<_, N_BYTES_U64>::construct(&mut cb, q.target_epoch(), q.exit_epoch());

            cb.condition(q.is_active(), |cb| {
                cb.require_zero("slashed is false for active validators", q.slashed());

                cb.require_true(
                    "activation_epoch <= target_epoch > exit_epoch for active validators",
                    target_gte_activation.expr() * target_lt_exit.expr(),
                )
            });

            config.target_gte_activation.insert(target_gte_activation);
            config.target_lt_exit.insert(target_lt_exit);

            cb.gate(q.selector() * q.is_validator())
        });

        meta.create_gate("committee constraints", |meta| {
            let q = queries(meta, &config);
            let mut cb = ConstraintBuilder::new(&mut config.cell_manager, MAX_DEGREE);
            cb.require_boolean("tag in [validator/committee]", q.tag());
            cb.require_zero("is_active is 0 for committees", q.is_active());
            cb.require_zero("is_attested is 0 for committees", q.is_attested());
            cb.require_zero("slashed is 0 for committees", q.slashed());

            cb.gate(q.selector() * q.is_committee())
        });

        config
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        // self.state_table.annotate_columns_in_region(region);
        // self.tag.annotate_columns_in_region(region, "tag");
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
    }
}

impl<F: Field> ValidatorsCircuitConfig<F> {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        committees: &[Committee],
        target_epoch: u64,
        challange: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                self.assign_with_region(
                    &mut region,
                    validators,
                    committees,
                    target_epoch,
                    challange,
                )
            },
        );

        Ok(())
    }

    fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        validators: &[Validator],
        committees: &[Committee],
        target_epoch: u64,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities(validators.iter(), committees.iter());

        let target_gte_activation = self
            .target_gte_activation
            .as_ref()
            .expect("target_gte_activation gadget is expected");
        let target_lt_exit = self
            .target_lt_exit
            .as_ref()
            .expect("target_lt_exited gadget is expected");

        let mut offset = 0;
        for entity in casper_entities.iter() {
            region.assign_advice(
                || "assign target epoch",
                self.target_epoch,
                offset,
                || Value::known(F::from(target_epoch)),
            )?; // TODO: assign from instance instead

            match entity {
                CasperEntity::Validator(validator) => {
                    // enable selector for the first row of each validator
                    region.assign_advice(
                        || "assign q_enabled",
                        self.is_validator,
                        offset,
                        || Value::known(F::one()),
                    )?;

                    target_gte_activation.assign(
                        region,
                        offset,
                        F::from(validator.activation_epoch),
                        F::from(target_epoch + 1),
                    );
                    target_lt_exit.assign(
                        region,
                        offset,
                        F::from(target_epoch),
                        F::from(validator.exit_epoch),
                    );

                    let validator_rows = validator.table_assignment(randomness);

                    assert_eq!(validator_rows.len(), STATE_ROWS_PER_VALIDATOR);

                    for (i, row) in validator_rows.into_iter().enumerate() {
                        self.validators_table
                            .assign_with_region(region, offset + i, &row)?;
                    }

                    offset += STATE_ROWS_PER_VALIDATOR;
                }
                CasperEntity::Committee(committee) => {
                    region.assign_advice(
                        || "assign is_committee",
                        self.is_committee,
                        offset,
                        || Value::known(F::one()),
                    )?;

                    let committee_rows = committee.table_assignment(randomness);

                    // TODO: assert_eq!(committee_rows.len(), STATE_ROWS_PER_COMMITEE);

                    for (i, row) in committee_rows.into_iter().enumerate() {
                        self.validators_table
                            .assign_with_region(region, offset + i, &row)?;
                    }

                    offset += STATE_ROWS_PER_COMMITEE;
                }
            }
        }

        // annotate circuit
        self.annotate_columns_in_region(region);

        Ok(())
    }

    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        let mut annotations = vec![
            (self.is_validator.into(), "q_enabled".to_string()),
            (self.storage_phase1.into(), "storage_phase1".to_string()),
            (self.target_epoch.into(), "epoch".to_string()),
        ];

        for (i, col) in self.byte_lookup.iter().copied().enumerate() {
            annotations.push((col.into(), format!("byte_lookup_{}", i)));
        }

        annotations
    }
}

/// State Circuit for proving RwTable is valid
#[derive(Default, Clone, Debug)]
pub struct ValidatorsCircuit<F> {
    pub(crate) validators: Vec<Validator>,
    pub(crate) committees: Vec<Committee>,
    target_epoch: u64,
    _f: PhantomData<F>,
}

impl<F: Field> ValidatorsCircuit<F> {
    /// make a new state circuit from an RwMap
    pub fn new(validators: Vec<Validator>, committees: Vec<Committee>, target_epoch: u64) -> Self {
        Self {
            validators,
            committees,
            target_epoch,
            _f: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for ValidatorsCircuit<F> {
    type Config = ValidatorsCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.validators.clone(),
            block.committees.clone(),
            block.target_epoch,
        )
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    /// Make the assignments to the ValidatorsCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "validators circuit",
            |mut region| {
                config.assign_with_region(
                    &mut region,
                    &self.validators,
                    &self.committees,
                    self.target_epoch,
                    challenges.sha256_input(),
                )
            },
        );

        Ok(())
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &ValidatorsCircuitConfig<F>) -> Queries<F> {
    Queries {
        q_enabled: meta.query_fixed(c.q_enabled, Rotation::cur()),
        target_epoch: meta.query_advice(c.target_epoch, Rotation::cur()),
        state_table: StateQueries {
            id: meta.query_advice(c.validators_table.id, Rotation::cur()),
            order: meta.query_advice(c.validators_table.id, Rotation::cur()),
            tag: meta.query_advice(c.validators_table.tag, Rotation::cur()),
            is_active: meta.query_advice(c.validators_table.is_active, Rotation::cur()),
            is_attested: meta.query_advice(c.validators_table.is_attested, Rotation::cur()),
            field_tag: meta.query_advice(c.validators_table.field_tag, Rotation::cur()),
            index: meta.query_advice(c.validators_table.index, Rotation::cur()),
            g_index: meta.query_advice(c.validators_table.gindex, Rotation::cur()),
            value: meta.query_advice(c.validators_table.value, Rotation::cur()),
            // vitual queries for tag == 'validator'
            balance: meta.query_advice(c.validators_table.value, Rotation::cur()),
            slashed: meta.query_advice(c.validators_table.value, Rotation::next()),
            activation_epoch: meta.query_advice(c.validators_table.value, Rotation(2)),
            exit_epoch: meta.query_advice(c.validators_table.value, Rotation(3)),
            pubkey_lo: meta.query_advice(c.validators_table.value, Rotation(4)),
            pubkey_hi: meta.query_advice(c.validators_table.value, Rotation(5)),
        },
    }
}

mod tests {
    use super::*;
    use crate::{
        table::state_table::StateTables,
        witness::{Committee, MerkleTrace, Validator},
    };
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::Circuit,
    };
    use itertools::Itertools;
    use std::{fs, marker::PhantomData, vec};

    #[derive(Debug, Clone)]
    struct TestValidators<F: Field> {
        validators_circuit: ValidatorsCircuit<F>,
        state_tree_trace: MerkleTrace,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestValidators<F> {
        type Config = (ValidatorsCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let args = ValidatorsCircuitArgs {
                state_tables: StateTables::dev_construct(meta),
            };

            (
                ValidatorsCircuitConfig::new(meta, args),
                Challenges::construct(meta),
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            config
                .0
                .state_tables
                .dev_load(&mut layouter, &self.state_tree_trace, challenge)?;
            self.validators_circuit.synthesize_sub(
                &config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_validators_circuit() {
        let k = 10;
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let committees: Vec<Committee> =
            serde_json::from_slice(&fs::read("../test_data/committees.json").unwrap()).unwrap();
        let state_tree_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();

        let circuit = TestValidators::<Fr> {
            validators_circuit: ValidatorsCircuit::new(validators, committees, 25),
            state_tree_trace,
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
