use std::{cell::RefCell, collections::HashMap, marker::PhantomData, vec};

use crate::{
    gadget::crypto::{
        CachedHashChip, Fp2Chip, Fp2Point, G2Chip, HashChip, HashToCurveCache, HashToCurveChip,
        Sha256Chip,
    },
    sha256_circuit::Sha256CircuitConfig,
    util::{print_fq2_dev, Challenges, IntoWitness, SubCircuit, SubCircuitConfig},
    witness::{self, Attestation, HashInput, HashInputChunk},
};
use eth_types::{AppCurveExt, Field, Spec};
use halo2_base::{
    gates::{builder::GateThreadBuilder, range::RangeConfig},
    safe_types::RangeChip,
    utils::CurveAffineExt,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    ecc::{EcPoint, EccChip},
    fields::{FieldChip, FieldExtConstructor},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use itertools::Itertools;
use pasta_curves::group::GroupEncoding;
use ssz_rs::Merkleized;
pub use witness::AttestationData;

pub const ZERO_HASHES: [[u8; 32]; 2] = [
    [0; 32],
    [
        245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35,
        32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75,
    ],
];

#[allow(type_alias_bounds)]
type FpChip<'chip, F, C: AppCurveExt> = halo2_ecc::fields::fp::FpChip<'chip, F, C::Fp>;

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

    fn new<S: Spec>(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let range = args.range;
        let sha256_config = args.sha256_config;
        Self {
            range,
            sha256_config,
        }
    }

    fn annotate_columns_in_region(&self, _region: &mut Region<'_, F>) {}
}

#[allow(type_alias_bounds)]
#[derive(Debug)]
pub struct AttestationsCircuitBuilder<'a, S: Spec, F: Field, const COMMITTEE_MAX_SIZE: usize>
where
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    builder: RefCell<GateThreadBuilder<F>>,
    attestations: &'a [Attestation<S>],
    range: &'a RangeChip<F>,
    fp_chip: FpChip<'a, F, S::SiganturesCurve>,
    zero_hashes: RefCell<HashMap<usize, HashInputChunk<QuantumCell<F>>>>,
    _spec: PhantomData<S>,
}

impl<'a, S: Spec, F: Field, const COMMITTEE_MAX_SIZE: usize>
    AttestationsCircuitBuilder<'a, S, F, COMMITTEE_MAX_SIZE>
where
    <S::SiganturesCurve as AppCurveExt>::Fq:
        FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
    pub fn new(
        builder: GateThreadBuilder<F>,
        attestations: &'a [Attestation<S>],
        range: &'a RangeChip<F>,
    ) -> Self {
        let fp_chip = FpChip::<F, S::SiganturesCurve>::new(
            range,
            S::SiganturesCurve::LIMB_BITS,
            S::SiganturesCurve::NUM_LIMBS,
        );
        Self {
            builder: RefCell::new(builder),
            range,
            attestations,
            fp_chip,
            zero_hashes: Default::default(),
            _spec: PhantomData,
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
        assert!(!self.attestations.is_empty(), "no attestations supplied");
        assert!(
            self.attestations.len() <= S::MAX_COMMITTEES_PER_SLOT * S::SLOTS_PER_EPOCH,
            "too many attestations supplied",
        );
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let sha256_chip = Sha256Chip::new(
            &config.sha256_config,
            self.range(),
            challenges.sha256_input(),
            None,
            0,
        );

        let hasher = CachedHashChip::new(&sha256_chip);

        let fp2_chip = self.fp2_chip();
        let g2_chip = EccChip::new(&fp2_chip);
        let h2c_chip = HashToCurveChip::<S, F, _>::new(&sha256_chip);

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
                            .digest::<64>(
                                (cp.epoch, cp.root.as_ref()).into_witness(),
                                ctx,
                                &mut region,
                            )
                            .unwrap()
                    });

                    let mut h2c_cache = HashToCurveCache::default();

                    for Attestation::<S> {
                        data, signature, ..
                    } in self.attestations.iter()
                    {
                        assert!(!signature.is_infinity());

                        let _signature = self.assign_signature(signature, &g2_chip, ctx);

                        let chunks = [
                            data.slot.into_witness(),
                            data.index.into_witness(),
                            data.beacon_block_root.as_ref().into_witness(),
                            source_root.output_bytes.into(),
                            target_root.output_bytes.into(),
                        ];

                        let signing_root =
                            self.merkleize_chunks(chunks, &hasher, ctx, &mut region)?;

                        assert_eq!(
                            data.clone().hash_tree_root().unwrap().as_ref().to_vec(),
                            signing_root
                                .iter()
                                .map(|e| e.value().get_lower_32() as u8)
                                .collect_vec(),
                            "invalid signing root"
                        );

                        let msg_point = h2c_chip.hash_to_curve::<S::SiganturesCurve>(
                            signing_root.into(),
                            self.fp_chip(),
                            ctx,
                            &mut region,
                            &mut h2c_cache,
                        )?;
                    }

                    let extra_assignments = hasher.take_extra_assignments();

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
        g2_chip: &G2Chip<F, S::SiganturesCurve>,
        ctx: &mut Context<F>,
    ) -> EcPoint<F, Fp2Point<F>> {
        let sig_affine = <S::SiganturesCurve as AppCurveExt>::Affine::from_bytes(
            &bytes_compressed.to_vec().try_into().unwrap(),
        )
        .unwrap();

        let (x, y) = sig_affine.into_coordinates();

        g2_chip.load_private_unchecked(ctx, (x, y))
    }

    fn merkleize_chunks<I: IntoIterator<Item = HashInputChunk<QuantumCell<F>>>>(
        &self,
        chunks: I,
        hasher: &'a CachedHashChip<F, Sha256Chip<'a, F>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error>
    where
        I::IntoIter: ExactSizeIterator,
    {
        let mut chunks = chunks.into_iter().collect_vec();
        let mut zero_hashes = self.zero_hashes.borrow_mut();
        let len_even = chunks.len() + chunks.len() % 2;
        let height = (len_even as f64).log2().ceil() as usize;

        for depth in 0..height {
            // Pad to even length using 32 zero bytes assigned as constants.
            let len_even = chunks.len() + chunks.len() % 2;
            let padded_chunks = chunks
                .into_iter()
                .pad_using(len_even, |_| {
                    zero_hashes
                        .entry(depth)
                        .or_insert_with(|| {
                            HashInputChunk::from(
                                ZERO_HASHES[depth].map(|b| ctx.load_constant(F::from(b as u64))),
                            )
                        })
                        .clone()
                })
                .collect_vec();

            chunks = padded_chunks
                .into_iter()
                .tuples()
                .map(|(left, right)| {
                    hasher
                        .digest::<64>(HashInput::TwoToOne(left, right), ctx, region)
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

    fn fp2_chip(&self) -> Fp2Chip<'_, F, S::SiganturesCurve> {
        Fp2Chip::<F, S::SiganturesCurve>::new(self.fp_chip())
    }

    fn fp_chip(&self) -> &FpChip<'_, F, S::SiganturesCurve> {
        &self.fp_chip
    }

    fn range(&self) -> &RangeChip<F> {
        self.range
    }
}

impl<'a, S: Spec, F: Field, const MAX_VALIDATORS_PER_COMMITTEE: usize> SubCircuit<F>
    for AttestationsCircuitBuilder<'a, S, F, MAX_VALIDATORS_PER_COMMITTEE>
where
    <S::SiganturesCurve as AppCurveExt>::Fq:
        FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
    [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
{
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
    use std::fs;

    use crate::{table::SHA256Table, witness::Validator};

    use super::*;
    use eth_types::Test;
    use halo2_base::gates::range::RangeStrategy;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Debug)]
    struct TestCircuit<'a, S: Spec, F: Field, const CMS: usize>
    where
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
        inner: AttestationsCircuitBuilder<'a, S, F, CMS>,
    }

    impl<'a, S: Spec, F: Field, const CMS: usize> TestCircuit<'a, S, F, CMS>
    where
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
        const NUM_ADVICE: &[usize] = &[30];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 5;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 16;
    }

    impl<'a, S: Spec, F: Field, const CMS: usize> Circuit<F> for TestCircuit<'a, S, F, CMS>
    where
        <S::SiganturesCurve as AppCurveExt>::Fq:
            FieldExtConstructor<<S::SiganturesCurve as AppCurveExt>::Fp, 2>,
        [(); S::MAX_VALIDATORS_PER_COMMITTEE]:,
    {
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
            let sha256_config = Sha256CircuitConfig::new::<Test>(meta, hash_table);
            let config = AttestationsCircuitConfig::new::<Test>(
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
    fn test_attestations_circuit() {
        let k = TestCircuit::<Test, Fr, { Test::MAX_VALIDATORS_PER_COMMITTEE }>::K;

        let range = RangeChip::default(
            TestCircuit::<Test, Fr, { Test::MAX_VALIDATORS_PER_COMMITTEE }>::LOOKUP_BITS,
        );
        let builder = GateThreadBuilder::new(false);
        builder.config(k, None);
        let attestations: Vec<Attestation<Test>> =
            serde_json::from_slice(&fs::read("../test_data/attestations.json").unwrap()).unwrap();

        let circuit = TestCircuit::<'_, Test, Fr, { Test::MAX_VALIDATORS_PER_COMMITTEE }> {
            inner: AttestationsCircuitBuilder::new(builder, &attestations, &range),
        };

        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
