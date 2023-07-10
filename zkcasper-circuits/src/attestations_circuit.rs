use std::{cell::RefCell, vec};

use crate::{
    aggregation_circuit::{LIMB_BITS, NUM_LIMBS},
    sha256_circuit::{
        chips::{AssignedHashResult, CachedSha256Chip, Sha256Chip},
        Sha256CircuitConfig,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig, IntoWitness},
    witness::{self, HashInput, HashInputRaw},
};
use eth_types::Field;
use halo2_base::{
    gates::{builder::GateThreadBuilder, range::RangeConfig, RangeInstructions},
    safe_types::RangeChip,
    Context, QuantumCell,
};
use halo2_ecc::{
    bn254::{Fp2Chip, FpChip},
    ecc::EccChip,
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::{bn256::G2Affine, group::GroupEncoding};
use itertools::Itertools;
use sha2::Sha256;
pub use witness::{AttestationData, IndexedAttestation};

pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;

#[derive(Clone, Debug)]
pub struct AttestationsCircuitConfig<F: Field> {
    range: RangeConfig<F>,
    sha256_config: Sha256CircuitConfig<F>,
}

pub struct AttestationsCircuitArgs<F: Field> {
    pub range: RangeConfig<F>,
    pub sha256_config: Sha256CircuitConfig<F>,
}

impl<F: Field> SubCircuitConfig<F> for AttestationsCircuitConfig<F> {
    type ConfigArgs = AttestationsCircuitArgs<F>;

    fn new(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let range = args.range;
        let sha256_config = args.sha256_config;
        Self {
            range,
            sha256_config,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {}
}

#[derive(Debug)]
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

        let sha256_chip = Sha256Chip::new(
            &config.sha256_config,
            self.range(),
            64,
            challenges.sha256_input(),
            None,
        );

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

                    let extra_assignments = sha256_chip.take_extra_assignments();

                    let _ = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        extra_assignments,
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

        let sig_affine =
            G2Affine::from_bytes(&attestation.signature.as_ref().try_into().unwrap()).unwrap();
    }

    fn assign_attestation_data(
        &self,
        data: &AttestationData,
        sha256_chip: &CachedSha256Chip<F>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<(), Error> {
        let source_root =
            sha256_chip.digest((data.source.epoch, data.source.root.as_ref()).into_witness(), ctx, region)?;
        let target_root =
            sha256_chip.digest((data.target.epoch, data.target.root.as_ref()).into_witness(), ctx, region)?;

        let padding_chunk = [0; 32].map(|b| ctx.load_constant(F::from(b)));

        let chunks: &[HashInputRaw<QuantumCell<F>>] = &[
            padding_chunk.into(),
            target_root.output_bytes.into(),
            source_root.output_bytes.into(),
            data.beacon_block_root.as_ref().into_witness(),
            data.index.into_witness(),
            data.slot.into_witness(),
        ];

        // let chunks = [
        //     data.slot.into(),
        //     data.index.into(),
        //     data.beacon_block_root.as_ref().into(),
        // ]
        // .map(|c: HashInputRaw<u8>| c.into_witness())
        // .into_iter()
        // .chain([
        //     source_root.output_bytes.into(),
        //     target_root.output_bytes.into(),
        //     padding_chunk.into(),
        // ]);

        // assert!(chunks.size_hint().0 % 2 == 0, "chunks must be even length");

        // chunks
        //     .tuple_windows()
        //     .map(|(left, right)| {
        //         sha256_chip.digest(HashInput::TwoToOne(left, right), ctx, region)
        //     });

        // let x = HashInput::TwoToOne(data.slot.into(), )

        Ok(())
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
    use crate::{sha256_circuit, table::SHA256Table};

    use super::*;
    use halo2_base::gates::range::RangeStrategy;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Debug)]
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
            let hash_table = SHA256Table::construct(meta);
            let sha256_config = Sha256CircuitConfig::new(meta, hash_table);
            let config = AttestationsCircuitConfig::new(
                meta,
                AttestationsCircuitArgs {
                    range,
                    sha256_config,
                },
            );

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
