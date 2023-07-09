use std::cell::RefCell;

use crate::{
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness, aggregation_circuit::{LIMB_BITS, NUM_LIMBS},
};
use eth_types::Field;
use halo2_base::{
    gates::{builder::GateThreadBuilder, range::RangeConfig, RangeInstructions},
    safe_types::RangeChip,
};
use halo2_ecc::{bn254::{Fp2Chip, FpChip}, ecc::EccChip};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::{bn256::G2Affine, group::GroupEncoding};
pub use witness::{AttestationData, IndexedAttestation};

pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;

#[derive(Clone, Debug)]
pub struct AttestationsCircuitConfig<F: Field> {
    range: RangeConfig<F>,
}

pub struct AttestationsCircuitArgs<F: Field> {
    pub range: RangeConfig<F>,
}

impl<F: Field> SubCircuitConfig<F> for AttestationsCircuitConfig<F> {
    type ConfigArgs = AttestationsCircuitArgs<F>;

    fn new(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let range = args.range;

        Self { range }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {}
}

#[derive(Clone, Debug)]
pub struct AttestationsCircuitBuilder<'a, F: Field> {
    builder: RefCell<GateThreadBuilder<F>>,
    attestations: &'a [IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>],
    range: &'a RangeChip<F>,
    fp_chip: FpChip<'a, F>,
}

impl<'a, F: Field> AttestationsCircuitBuilder<'a, F> {
    pub fn new(
        builder: GateThreadBuilder<F>,
        attestations: &'a [IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>],
        range: &'a RangeChip<F>,
    ) -> Self {
        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMBS);
        Self {
            builder: RefCell::new(builder),
            range,
            attestations,
            fp_chip,
        }
    }

    pub fn synthesize(
        &self,
        config: &AttestationsCircuitConfig<F>,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        layouter
            .assign_region(
                || "AggregationCircuitBuilder generated circuit",
                |mut region| {
                    config.annotate_columns_in_region(&mut region);
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut region = region;

                    let builder = &mut self.builder.borrow_mut();
                    let ctx = builder.main(0);

                    for attestation in self.attestations.iter() {
                        let _ = self.assign_attestation(attestation);

                    }

                    let halo2_base::gates::builder::KeygenAssignments::<F> {
                        assigned_advices, ..
                    } = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        Default::default(),
                    );

                    Ok(())
                },
            )
            .unwrap();
    }

    fn assign_attestation(&self, attestation: &IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>) {
        let range = self.range();
        let gate = range.gate();
        let g2_chip = EccChip::new(&self.fp2_chip());

        let sig_affine = G2Affine::from_bytes(&attestation.signature.as_ref().try_into().unwrap()).unwrap();
    }

    fn assign_attestation_data(&self) {
        
    }

    fn fp2_chip(&self) -> Fp2Chip<'_, F> {
        Fp2Chip::new(self.fp_chip())
    }

    fn fp_chip(&self) -> &FpChip<'_, F> {
        &self.fp_chip
    }

    fn range(&self) -> &RangeChip<F> {
        self.range
    }
}

impl<'a, F: Field> SubCircuit<F> for AttestationsCircuitBuilder<'a, F> {
    type Config = AttestationsCircuitConfig<F>;

    fn new_from_block(_block: &witness::Block<F>) -> Self {
        todo!()
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &mut Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.synthesize(config, challenges, layouter);

        Ok(())
    }

    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::range::RangeStrategy;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Debug, Clone)]
    struct TestCircuit<'a, F: Field> {
        inner: AttestationsCircuitBuilder<'a, F>,
    }

    impl<'a, F: Field> TestCircuit<'a, F> {
        const NUM_ADVICE: &[usize] = &[6, 1];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 1;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 14;
    }

    impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
        type Config = (AttestationsCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                Self::NUM_ADVICE,
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );
            let config = AttestationsCircuitConfig::new(meta, AttestationsCircuitArgs { range });

            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            self.inner.synthesize_sub(
                &mut config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_aggregation_circuit() {
        let k = TestCircuit::<Fr>::K;

        let range = RangeChip::default(TestCircuit::<Fr>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        builder.config(k, None);
        let attestations = vec![];
        let circuit = TestCircuit::<'_, Fr> {
            inner: AttestationsCircuitBuilder::new(builder, &attestations, &range),
        };

        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
