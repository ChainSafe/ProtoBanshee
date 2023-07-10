use std::{cell::RefCell, vec};

use crate::{
    aggregation_circuit::{LIMB_BITS, NUM_LIMBS},
    sha256_circuit::{
        chips::{CachedSha256Chip, Sha256Chip},
        Sha256CircuitConfig,
    },
    util::{Challenges, IntoWitness, SubCircuit, SubCircuitConfig},
    witness::{self, HashInput, HashInputChunk},
};
use eth_types::Field;
use halo2_base::{
    gates::{builder::GateThreadBuilder, range::RangeConfig},
    safe_types::RangeChip,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bn254::{Fp2Chip, FpChip, FqPoint},
    ecc::{EcPoint, EccChip},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::{bn256::G2Affine, group::GroupEncoding};
use itertools::Itertools;
pub use witness::{AttestationData, IndexedAttestation};

pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
pub const MAX_COMMITTEES_PER_SLOT: usize = 64;
pub const SLOTS_PER_EPOCH: usize = 32;

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

    fn annotate_columns_in_region(&self, _region: &mut Region<'_, F>) {}
}

#[derive(Debug)]
pub struct AttestationsCircuitBuilder<'a, F: Field> {
    builder: RefCell<GateThreadBuilder<F>>,
    attestations: &'a [IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>],
    range: &'a RangeChip<F>,
    fp_chip: FpChip<'a, F>,
    padding_chunk: RefCell<Option<HashInputChunk<QuantumCell<F>>>>,
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
            padding_chunk: Default::default(),
        }
    }

    /// assumptions:
    /// - partial attestations are aggregated into full attestations
    /// - number of attestations is less than MAX_COMMITTEES_PER_SLOT * SLOTS_PER_EPOCH
    /// - all attestation have same source and target epoch
    pub fn synthesize(
        &self,
        config: &AttestationsCircuitConfig<F>,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) {
        assert!(self.attestations.len() > 0, "no attestations supplied");
        assert!(
            self.attestations.len() <= MAX_COMMITTEES_PER_SLOT * SLOTS_PER_EPOCH,
            "too many attestations supplied",
        );
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let hasher = CachedSha256Chip::new(Sha256Chip::new(
            &config.sha256_config,
            self.range(),
            64,
            challenges.sha256_input(),
            None,
        ));

        let fp2_chip = self.fp2_chip();
        let g2_chip = EccChip::new(&fp2_chip);

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

                    let [source_root, target_root] = [
                        self.attestations[0].data.source.clone(),
                        self.attestations[0].data.target.clone(),
                    ]
                    .map(|cp| {
                        hasher
                            .digest(
                                (cp.epoch, cp.root.as_ref()).into_witness(),
                                ctx,
                                &mut region,
                            )
                            .unwrap()
                    });

                    for IndexedAttestation {
                        data, signature, ..
                    } in self.attestations.iter() {
                        assert!(!signature.is_infinity());

                        let _signature = self.assign_signature(&signature, &g2_chip, ctx);

                        let chunks = [
                            data.slot.into_witness(),
                            data.index.into_witness(),
                            data.beacon_block_root.as_ref().into_witness(),
                            source_root.output_bytes.into(),
                            target_root.output_bytes.into(),
                        ];

                        self.merkleize_chunks(chunks, &hasher, ctx, &mut region)?;
                    }

                    let extra_assignments = hasher.inner.take_extra_assignments();

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

    fn assign_signature(
        &self,
        bytes_compressed: &[u8],
        g2_chip: &EccChip<'a, F, Fp2Chip<'a, F>>,
        ctx: &mut Context<F>,
    ) -> EcPoint<F, FqPoint<F>> {
        let sig_affine = G2Affine::from_bytes(
            &bytes_compressed
                .try_into()
                .expect("signature bytes leath not match"),
        )
        .unwrap();

        g2_chip.load_private_unchecked(ctx, (sig_affine.x, sig_affine.y))
    }

    fn merkleize_chunks<I: IntoIterator<Item = HashInputChunk<QuantumCell<F>>>>(
        &self,
        chunks: I,
        hasher: &CachedSha256Chip<F>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error>
    where
        I::IntoIter: ExactSizeIterator,
    {
        let chunks = chunks.into_iter();

        // Pad to even length using 32 zero bytes assigned as constants.
        let len_even = chunks.len() + chunks.len() % 2;
        let mut chunks = chunks
            .pad_using(len_even, |_| {
                self.padding_chunk
                    .borrow_mut()
                    .get_or_insert_with(|| {
                        HashInputChunk::from([0; 32].map(|b| ctx.load_constant(F::from(b))))
                    })
                    .clone()
            })
            .collect_vec();

        let tree_depth = (len_even as f64).log2().ceil() as usize;

        for _ in 0..tree_depth {
            chunks = chunks
                .into_iter()
                .tuple_windows()
                .map(|(left, right)| {
                    hasher
                        .digest(HashInput::TwoToOne(left, right), ctx, region)
                        .map(|res| res.output_bytes.into())
                })
                .collect::<Result<Vec<_>, _>>()?;
        }

        assert_eq!(chunks.len(), 1, "merkleize_chunks: expected one chunk");

        let root = chunks.pop().unwrap().map(|cell| match cell {
            QuantumCell::Existing(av) => av,
            _ => unreachable!(),
        });

        Ok(root.bytes)
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
    use crate::{table::SHA256Table};

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
