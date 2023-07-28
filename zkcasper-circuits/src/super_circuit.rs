use std::{cell::RefCell, rc::Rc};

use eth_types::{AppCurveExt, Field, Spec};
use ff::PrimeField;
use halo2_base::{
    gates::{
        builder::GateThreadBuilder,
        range::{RangeConfig, RangeStrategy},
    },
    safe_types::RangeChip,
};
use halo2_ecc::fields::FieldExtConstructor;
use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    aggregation_circuit::AggregationCircuitBuilder,
    attestations_circuit::{
        AttestationsCircuitArgs, AttestationsCircuitBuilder, AttestationsCircuitConfig, BlsCurveExt,
    },
    sha256_circuit::{Sha256Circuit, Sha256CircuitConfig},
    state_circuit::{StateCircuit, StateCircuitArgs, StateCircuitConfig},
    table::{state_table::StateTables, LookupTable, Sha256Table, ValidatorsTable},
    util::{Challenges, SubCircuit, SubCircuitBuilder, SubCircuitConfig},
    validators_circuit::{ValidatorsCircuit, ValidatorsCircuitArgs, ValidatorsCircuitConfig},
    witness::State,
};

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field> {
    state_circuit: StateCircuitConfig<F>,
    validators_table: ValidatorsTable,
    validators_circuit: ValidatorsCircuitConfig<F>,
    sha256_table: Sha256Table,
    sha256_circuit: Sha256CircuitConfig<F>,
    range: RangeConfig<F>,
    attestations_circuit: AttestationsCircuitConfig<F>,
}

impl<F: Field> SuperCircuitConfig<F> {
    const NUM_ADVICE: &[usize] = &[80];
    const NUM_FIXED: usize = 1;
    const NUM_LOOKUP_ADVICE: usize = 15;
    const LOOKUP_BITS: usize = 8;
    const K: usize = 17;
}

impl<F: Field> SubCircuitConfig<F> for SuperCircuitConfig<F> {
    type ConfigArgs = ();

    fn new<S: Spec>(meta: &mut ConstraintSystem<F>, _: Self::ConfigArgs) -> Self {
        let sha256_table = Sha256Table::construct(meta);
        let validators_table = ValidatorsTable::construct::<S, F>(meta);

        let sha256_circuit = Sha256CircuitConfig::new::<S>(meta, sha256_table.clone());

        let state_circuit = StateCircuitConfig::new::<S>(
            meta,
            StateCircuitArgs {
                sha256_table: sha256_table.clone(),
            },
        );

        let validators_circuit = ValidatorsCircuitConfig::new::<S>(
            meta,
            ValidatorsCircuitArgs {
                state_tables: state_circuit.state_tables.clone(),
            },
        );

        let range = RangeConfig::configure(
            meta,
            RangeStrategy::Vertical,
            Self::NUM_ADVICE,
            &[Self::NUM_LOOKUP_ADVICE],
            Self::NUM_FIXED,
            Self::LOOKUP_BITS,
            Self::K,
        );

        let attestations_circuit = AttestationsCircuitConfig::new::<S>(
            meta,
            AttestationsCircuitArgs::<F> {
                sha256_config: sha256_circuit.clone(),
                range: range.clone(),
            },
        );

        Self {
            state_circuit,
            validators_table,
            validators_circuit,
            sha256_table,
            sha256_circuit,
            range,
            attestations_circuit,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut halo2_proofs::circuit::Region<F>) {
        self.sha256_table.annotate_columns_in_region(region);
        self.sha256_circuit.annotate_columns_in_region(region);
        self.state_circuit.annotate_columns_in_region(region);
        self.validators_table.annotate_columns_in_region(region);
        self.validators_circuit.annotate_columns_in_region(region);
        self.attestations_circuit.annotate_columns_in_region(region);
    }
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Clone, Debug)]
pub struct SuperCircuit<'a, S: Spec + Sync, F: Field>
where
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    state_circuit: StateCircuit<'a, S, F>,
    validators_circuit: ValidatorsCircuit<'a, S, F>,
    sha256_circuit: Sha256Circuit<'a, S, F>,
    builder: Rc<RefCell<GateThreadBuilder<F>>>,
    aggregation_circuit: AggregationCircuitBuilder<'a, S, F>,
    attestations_circuit: AttestationsCircuitBuilder<'a, S, F>,
}

impl<'a, S: Spec + Sync, F: Field> SuperCircuit<'a, S, F>
where
    S::SiganturesCurve: BlsCurveExt,
    <S::SiganturesCurve as AppCurveExt>::Fq:
        FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    pub fn new_from_block(block: &'a State<S, F>) -> Self {
        let state_circuit = StateCircuit::new_from_state(block);
        let validators_circuit = ValidatorsCircuit::new_from_state(block);
        let sha256_circuit = Sha256Circuit::new_from_state(block);

        let builder = GateThreadBuilder::new(false);
        let builder = Rc::new(RefCell::new(builder));
        let aggregation_circuit = AggregationCircuitBuilder::new_from_state(builder.clone(), block);
        let attestations_circuit =
            AttestationsCircuitBuilder::new_from_state(builder.clone(), block);

        Self {
            state_circuit,
            validators_circuit,
            sha256_circuit,
            builder,
            aggregation_circuit,
            attestations_circuit,
        }
    }
}

impl<'a, S: Spec + Sync, F: Field> Circuit<F> for SuperCircuit<'a, S, F>
where
    S::SiganturesCurve: BlsCurveExt,
    <S::SiganturesCurve as AppCurveExt>::Fq:
        FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    type Config = SuperCircuitConfig<F>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config::new::<S>(meta, ())
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge()));
        self.sha256_circuit.synthesize_sub(
            &config.sha256_circuit,
            &challenges,
            &mut layouter,
            (),
        )?;
        self.state_circuit
            .synthesize_sub(&config.state_circuit, &challenges, &mut layouter, ())?;
        let validator_cells = self.validators_circuit.synthesize_sub(
            &config.validators_circuit,
            &challenges,
            &mut layouter,
            (),
        )?;
        let aggregated_pubkeys = self.aggregation_circuit.synthesize_sub(
            &config.range,
            &challenges,
            &mut layouter,
            validator_cells,
        )?;
        self.attestations_circuit.synthesize_sub(
            &config.attestations_circuit,
            &challenges,
            &mut layouter,
            aggregated_pubkeys,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use eth_types::Test;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;

    use super::*;

    #[test]
    fn test_attestations_circuit() {
        let block = State::<Test, Fr>::default();
        let circuit = SuperCircuit::<Test, Fr>::new_from_block(&block);
        let prover = MockProver::<Fr>::run(18, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
