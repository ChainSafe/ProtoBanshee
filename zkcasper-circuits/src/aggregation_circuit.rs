use crate::{
    table::{LookupTable, ValidatorsTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, Committee, Validator},
};
use eth_types::*;
use gadgets::util::rlc;
use halo2_base::{
    gates::{
        builder::GateThreadBuilder,
        flex_gate::GateInstructions,
        range::{RangeChip, RangeConfig, RangeInstructions},
    },
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::ProperUint,
    bn254::FpPoint,
    ecc::{EcPoint, EccChip},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::{
    bn256::G1Affine,
    group::{ff::PrimeField, GroupEncoding, UncompressedEncoding},
    CurveAffine,
};
use itertools::Itertools;
use num_bigint::BigUint;
use std::cell::RefCell;
use types::Spec;

// TODO: Use halo2_ccc::bls12_381::FpChip after carry mod issue is resolved in halo2-lib.
// for details see: https://github.com/flyingnobita/halo2-lib-no-fork/blob/bls12-381/halo2-ecc/src/bls12_381/notes.md
pub type FpChip<'range, F> = halo2_ecc::fields::fp::FpChip<'range, F, halo2curves::bn256::Fq>;

// TODO: move this into Spec trait
pub const G1_FQ_BYTES: usize = 32; // TODO: 48 for BLS12-381.
pub const G1_BYTES_UNCOMPRESSED: usize = G1_FQ_BYTES * 2;
pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;

#[derive(Clone, Debug)]
pub struct AggregationCircuitConfig<F: Field> {
    validators_table: ValidatorsTable,
    range: RangeConfig<F>,
}

pub struct AggregationCircuitArgs<F: Field> {
    pub validators_table: ValidatorsTable,
    pub range: RangeConfig<F>,
}

impl<F: Field> SubCircuitConfig<F> for AggregationCircuitConfig<F> {
    type ConfigArgs = AggregationCircuitArgs<F>;

    fn new<S: Spec>(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs, spec: S) -> Self {
        let validators_table = args.validators_table;
        let range = args.range;

        Self {
            validators_table,
            range,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.validators_table.annotate_columns_in_region(region);
    }
}

#[derive(Clone, Debug)]
pub struct AggregationCircuitBuilder<'a, F: Field> {
    builder: RefCell<GateThreadBuilder<F>>,
    range: &'a RangeChip<F>,
    fp_chip: FpChip<'a, F>,
    // Witness
    validators: &'a [Validator],
    _committees: &'a [Committee],
}

impl<'a, F: Field> AggregationCircuitBuilder<'a, F> {
    pub fn new(
        builder: GateThreadBuilder<F>,
        validators: &'a [Validator],
        committees: &'a [Committee],
        range: &'a RangeChip<F>,
    ) -> Self {
        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMBS);
        Self {
            builder: RefCell::new(builder),
            range,
            fp_chip,
            validators,
            _committees: committees,
        }
    }

    pub fn synthesize(
        &self,
        config: &AggregationCircuitConfig<F>,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) {
        config
            .range
            .load_lookup_table(layouter)
            .expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let _witness_gen_only = self.builder.borrow().witness_gen_only();

        layouter
            .assign_region(
                || "AggregationCircuitBuilder generated circuit",
                |mut region| {
                    config.annotate_columns_in_region(&mut region);
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let builder = &mut self.builder.borrow_mut();
                    let ctx = builder.main(0);
                    let (_aggregated_pubkeys, pubkeys_compressed) = self.process_validators(ctx);

                    let ctx = builder.main(1);

                    let randomness = QuantumCell::Constant(
                        halo2_base::utils::value_to_option(challenges.sha256_input().clone())
                            .unwrap(),
                    );
                    let pubkey_rlcs = pubkeys_compressed
                        .into_iter()
                        .map(|compressed| {
                            self.get_rlc(&compressed[..G1_FQ_BYTES], &randomness, ctx)
                        })
                        .collect_vec();

                    let halo2_base::gates::builder::KeygenAssignments::<F> {
                        assigned_advices, ..
                    } = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        Default::default(),
                    );

                    // check that the assigned compressed encoding of pubkey used for constructiong affine point
                    // is consistent with bytes used in validators table
                    // assumption: order of self.validators is same as in BeaconState.validators so we treat iterator index as validator id
                    for (i, assigned_rlc) in pubkey_rlcs.into_iter().enumerate() {
                        // convert halo2lib `AssignedValue` into vanilla Halo2 `Cell`
                        let cells = assigned_rlc
                            .into_iter()
                            .filter_map(|c| c.cell)
                            .filter_map(|ctx_cell| {
                                assigned_advices.get(&(ctx_cell.context_id, ctx_cell.offset))
                            })
                            .map(|&(cell, _)| cell);

                        // get the corresponding cached cells from the validators table
                        let vs_table_cells = config
                            .validators_table
                            .pubkey_cells
                            .get(i)
                            .expect("pubkey cells for validator id");

                        // enforce equality
                        for (left, &right) in cells.zip_eq(vs_table_cells) {
                            region.constrain_equal(left, right)?;
                        }
                    }

                    Ok(())
                },
            )
            .unwrap();
    }

    fn process_validators(
        &self,
        ctx: &mut Context<F>,
    ) -> (
        Vec<EcPoint<F, FpPoint<F>>>,
        Vec<[AssignedValue<F>; G1_FQ_BYTES]>,
    ) {
        let range = self.range();

        let fp_chip = self.fp_chip();
        let g1_chip = self.g1_chip();

        let mut pubkeys_compressed = vec![];
        let mut aggregated_pubkeys = vec![];

        for (_committee, validators) in self
            .validators
            .into_iter()
            .group_by(|v| v.committee)
            .into_iter()
        {
            let mut in_committee_pubkeys = vec![];

            for validator in validators {
                let pk_compressed = validator.pubkey[..G1_FQ_BYTES].to_vec();

                // FIXME: replace with retriving y coordinate from cached map.
                let pk_affine =
                    G1Affine::from_bytes(&pk_compressed.as_slice().try_into().unwrap()).unwrap();

                // FIXME: constraint y coordinate bytes.
                let assigned_uncompressed: [AssignedValue<F>; G1_BYTES_UNCOMPRESSED] = ctx
                    .assign_witnesses(
                        pk_affine
                            .to_uncompressed()
                            .as_ref()
                            .iter()
                            .map(|&b| F::from(b as u64)),
                    )
                    .try_into()
                    .unwrap();

                // load masked bit from compressed representation
                let masked_byte = ctx.load_witness(F::from(pk_compressed[G1_FQ_BYTES - 1] as u64));
                let cleared_byte = self.clear_ysign_mask(&masked_byte, ctx);
                // constraint that the loaded masked byte is consistent with the assigned bytes used to construct the point.
                ctx.constrain_equal(&cleared_byte, &assigned_uncompressed[G1_FQ_BYTES - 1]);

                // cache assigned compressed pubkey bytes where each byte is constrainted with pubkey point.
                pubkeys_compressed.push({
                    let mut compressed_bytes = assigned_uncompressed[..G1_FQ_BYTES - 1].to_vec();
                    compressed_bytes.push(masked_byte);
                    compressed_bytes.try_into().unwrap()
                });

                in_committee_pubkeys.push(self.uncompressed_to_g1affine(
                    assigned_uncompressed,
                    &pk_affine,
                    ctx,
                ));
            }

            // let pk_affine = G1Affine::random(&mut rand::thread_rng());
            aggregated_pubkeys.push(g1_chip.sum::<G1Affine>(ctx, in_committee_pubkeys));
        }

        (aggregated_pubkeys, pubkeys_compressed)
    }

    /// Calculates RLCs (1 for each of two chacks of BLS12-381) for compresed bytes of pubkey.
    /// The resulted bigints should be equal to one used validators table.
    pub fn get_rlc(
        &self,
        assigned_bytes: &[AssignedValue<F>],
        randomness: &QuantumCell<F>,
        ctx: &mut Context<F>,
    ) -> [AssignedValue<F>; 2] {
        assert_eq!(assigned_bytes.len(), G1_FQ_BYTES);
        let gate = self.range().gate();

        // TODO: remove next 2 lines after switching to bls12-381
        let mut assigned_bytes = assigned_bytes.to_vec();
        assigned_bytes.resize(48, ctx.load_zero());

        assigned_bytes
            .chunks(32)
            .into_iter()
            .map(|values| rlc::assigned_value(values, randomness, gate, ctx))
            .collect_vec()
            .try_into()
            .unwrap()
    }

    /// Clears the sign mask bit (MSB) of a last byte of compressed pubkey.
    /// This function emulates bitwise and on 01111111 (decimal=127): `b & 127` = c
    fn clear_ysign_mask(&self, b: &AssignedValue<F>, ctx: &mut Context<F>) -> AssignedValue<F> {
        let range = self.range();
        let gate = range.gate();

        // Decomposing only the first bit (MSB): b_shift_msb = b * 2 mod 256 which is equivalent to b <<= 1
        let b_shift_msb = gate.mul(ctx, *b, QuantumCell::Constant(F::from(2)));
        let b_shift_msb = range.div_mod(ctx, b_shift_msb, BigUint::from(256u64), 8).1;

        // Note: to get "sign" bit:
        // let bit = b / 128; // equivalent to (a & 128) >> 7;
        // gate.assert_bit(ctx, bit)

        // Composing back to the original number but zeroing the first bit (MSB)
        // c = b_shift_msb / 2 + bit * 128 = b_shift_msb / 2 (since bit := 0)
        range.div_mod(ctx, b_shift_msb, BigUint::from(2u64), 8).0
    }

    /// Converts uncompressed pubkey bytes to G1Affine point.
    pub fn uncompressed_to_g1affine(
        &self,
        assigned_bytes: [AssignedValue<F>; G1_BYTES_UNCOMPRESSED],
        pk_affine: &G1Affine,
        ctx: &mut Context<F>,
    ) -> EcPoint<F, FpPoint<F>> {
        let range = self.range();
        let gate = range.gate();
        let fp_chip = self.fp_chip();

        let two = F::from(2);
        let f256 = ctx.load_constant(two.pow_const(8));

        // TODO: try optimized solution if LIMB_BITS i a multiple of 8:
        // https://github.com/axiom-crypto/axiom-eth/blob/6d2a4acf559a8716b867a715f3acfab745fbad3f/src/util/mod.rs#L419
        let bytes_per_limb = G1_FQ_BYTES / NUM_LIMBS + 1;
        let field_limbs: Vec<[_; NUM_LIMBS]> = assigned_bytes
            .chunks(G1_FQ_BYTES)
            .map(|fq_bytes| {
                fq_bytes
                    .chunks(bytes_per_limb)
                    .map(|chunk| {
                        chunk.iter().rev().fold(ctx.load_zero(), |acc, &byte| {
                            gate.mul_add(ctx, acc, f256, byte)
                        })
                    })
                    .collect_vec()
                    .try_into()
                    .unwrap()
            })
            .collect_vec();

        let pk_coords = pk_affine.coordinates().unwrap();

        let x = {
            let assigned_uint = ProperUint::new(field_limbs[0].to_vec());
            let value = BigUint::from_bytes_le(pk_coords.x().to_repr().as_ref());
            assigned_uint.into_crt(ctx, gate, value, &fp_chip.limb_bases, LIMB_BITS)
        };
        let y = {
            let assigned_uint = ProperUint::new(field_limbs[1].to_vec());
            let value = BigUint::from_bytes_le(pk_coords.y().to_repr().as_ref());
            assigned_uint.into_crt(ctx, gate, value, &fp_chip.limb_bases, LIMB_BITS)
        };

        EcPoint::new(x, y)
    }

    fn g1_chip(&'a self) -> EccChip<'a, F, FpChip<'a, F>> {
        EccChip::new(self.fp_chip())
    }

    fn fp_chip(&self) -> &FpChip<'a, F> {
        &self.fp_chip
    }

    fn range(&self) -> &RangeChip<F> {
        self.range
    }
}

impl<'a, F: Field> SubCircuit<F> for AggregationCircuitBuilder<'a, F> {
    type Config = AggregationCircuitConfig<F>;

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

    use super::*;
    use halo2_base::gates::range::RangeStrategy;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use types::Test as S;

    #[derive(Debug, Clone)]
    struct TestCircuit<'a, F: Field> {
        inner: AggregationCircuitBuilder<'a, F>,
    }

    impl<'a, F: Field> TestCircuit<'a, F> {
        const NUM_ADVICE: &[usize] = &[6, 1];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 1;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 14;
    }

    impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
        type Config = (AggregationCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let validators_table = ValidatorsTable::construct(meta);
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                Self::NUM_ADVICE,
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );
            let config = AggregationCircuitConfig::new(
                meta,
                AggregationCircuitArgs {
                    validators_table,
                    range,
                },
                S,
            );

            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            config.0.validators_table.dev_load(
                &mut layouter,
                self.inner.validators,
                self.inner._committees,
                challenge,
            )?;
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
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let committees: Vec<Committee> =
            serde_json::from_slice(&fs::read("../test_data/committees.json").unwrap()).unwrap();

        let range = RangeChip::default(TestCircuit::<Fr>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        builder.config(k, None);
        let circuit = TestCircuit::<'_, Fr> {
            inner: AggregationCircuitBuilder::new(builder, &validators, &committees, &range),
        };

        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
