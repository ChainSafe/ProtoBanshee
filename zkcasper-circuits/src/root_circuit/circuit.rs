use eth_types::Field;
use halo2_base::gates::builder::{CircuitBuilderStage, RangeWithInstanceConfig};
use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Layouter},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::kzg::commitment::ParamsKZG,
};
use halo2curves::bn256::{Bn256, Fr};
use itertools::Itertools;
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, CircuitExt, Snark, SHPLONK};

#[derive(Clone)]
pub struct SnarkAggregationCircuit<const N_SNARK: usize> {
    pub aggregation_circuit: AggregationCircuit,
    prev_instances: Vec<Vec<Fr>>,
}

impl<const N_SNARK: usize> SnarkAggregationCircuit<N_SNARK> {
    /// Creates a new WrappedAggregationCircuit
    pub fn new(
        stage: CircuitBuilderStage,
        params: &ParamsKZG<Bn256>,
        lookup_bits: usize,
        snarks: impl IntoIterator<Item = Snark>,
    ) -> Self {
        let snarks = snarks.into_iter().collect_vec();

        let prev_instances = snarks
            .iter()
            .flat_map(|snark| snark.instances.iter())
            .cloned()
            .collect_vec();

        let aggregation_circuit =
            AggregationCircuit::new::<SHPLONK>(stage, None, lookup_bits, params, snarks);

        Self {
            aggregation_circuit,
            prev_instances,
        }
    }
}

impl<const N_SNARK: usize> Circuit<Fr> for SnarkAggregationCircuit<N_SNARK> {
    type Config = RangeWithInstanceConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let aggregation_circuit = AggregationCircuit::without_witnesses(&self.aggregation_circuit);

        let prev_instances: Vec<Vec<Fr>> = vec![Vec::new(); N_SNARK];

        Self {
            aggregation_circuit,
            prev_instances,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        AggregationCircuit::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        self.aggregation_circuit.synthesize(config, layouter)?;

        Ok(())
    }
}

impl<const N_SNARK: usize> CircuitExt<Fr> for SnarkAggregationCircuit<N_SNARK> {
    /// Returns the number of instances of the circuit. For example, for a case of 2 snarks input with 1 instance column each with 4 rows, it should be `[4, 4, 16]`. Where 16 are `num_instance` from the aggregation circuit
    fn num_instance(&self) -> Vec<usize> {
        let mut num_instance = self
            .prev_instances
            .iter()
            .map(|instance| instance.len())
            .collect_vec();

        num_instance.push(self.aggregation_circuit.num_instance()[0]);

        num_instance
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        let mut instances = self.prev_instances.clone();
        instances.push(self.aggregation_circuit.instances()[0].clone());
        instances
    }
}
