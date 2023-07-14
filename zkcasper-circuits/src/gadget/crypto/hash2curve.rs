//! The chip that implements `draft-irtf-cfrg-hash-to-curve-16`
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use std::{cell::RefCell, iter, marker::PhantomData};

use eth_types::{Field, Spec};
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions, SafeBytes32, SafeTypeChip},
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{CRTInteger, ProperCrtUint, ProperUint},
    fields::{fp::FpChip, vector::FieldVector, FieldChip},
};
use halo2_proofs::{circuit::Region, plonk::Error};
use halo2curves::group::GroupEncoding;
use itertools::Itertools;
use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint};

use crate::{
    util::{decode_into_field, decode_into_field_be, decode_into_field_modp},
    witness::HashInput,
};

use super::sha256::HashChip;

const G2_EXT_DEGREE: usize = 2;

// L = ceil((ceil(log2(p)) + k) / 8) (see section 5 of ietf draft link above)
const L: usize = 64;

type Fp2Point<F> = FieldVector<ProperCrtUint<F>>;

#[derive(Debug)]
pub struct HashToCurveChip<S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: HC,
    assigned_dst_with_len: RefCell<Option<Vec<AssignedValue<F>>>>,
    binary_bases: RefCell<Option<Vec<AssignedValue<F>>>>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field, HC: HashChip<F>> HashToCurveChip<S, F, HC> {
    pub fn new(hash_chip: HC) -> Self {
        Self {
            hash_chip,
            assigned_dst_with_len: Default::default(),
            binary_bases: Default::default(),
            _spec: PhantomData,
        }
    }

    pub fn hash_to_field<FP: ScalarField>(
        &self,
        msg: HashInput<QuantumCell<F>>,
        fp_chip: &FpChip<F, FP>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<[Fp2Point<F>; 2], Error> {
        //
        let range = self.hash_chip.range();
        let gate = range.gate();
        let safe_types = SafeTypeChip::new(range);

        // constants
        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::one());

        let assigned_msg = msg.into_assigned(ctx).to_vec();

        let len_in_bytes = 2 * G2_EXT_DEGREE * L;
        let extended_msg = self.expand_message_xmd(assigned_msg, len_in_bytes, ctx, region)?;

        let limb_bases = self.binary_bases.borrow_mut().get_or_insert_with(|| {
            S::limb_bytes_bases()
                .into_iter()
                .map(|base| ctx.load_constant(base))
                .collect()
        });

        // 2^256
        let two_pow_256 = fp_chip.load_constant_uint(ctx, BigUint::from(2u8).pow(256));

        let mut fst = true;
        let u = extended_msg
            .chunks(L)
            .chunks(G2_EXT_DEGREE)
            .into_iter()
            .map(|elm_chunk| {
                FieldVector(
                    elm_chunk
                        .map(|tv| {
                            let mut buf = vec![zero; S::FQ_BYTES];
                            let rem = S::FQ_BYTES - 32;
                            buf[rem..].copy_from_slice(&tv[..32]);
                            let lo = decode_into_field_be::<S, F, _>(
                                buf.to_vec(),
                                &fp_chip.limb_bases,
                                gate,
                                ctx,
                            );

                            buf[rem..].copy_from_slice(&tv[32..]);
                            let hi = decode_into_field_be::<S, F, _>(
                                buf.to_vec(),
                                &fp_chip.limb_bases,
                                gate,
                                ctx,
                            );

                            let lo_2_256 = fp_chip.mul_no_carry(ctx, lo.clone(), two_pow_256.clone());
                            let lo_2_356_hi = fp_chip.add_no_carry(ctx, lo_2_256, hi.clone());
                            fp_chip.carry_mod(ctx, lo_2_356_hi)
                        })
                        .collect_vec(),
                )
            })
            .collect_vec()
            .try_into()
            .unwrap();

        Ok(u)
    }

    /// Produces a uniformly random byte string using a cryptographic hash function H that outputs b bits
    ///
    /// Implements [section 5.3 of `draft-irtf-cfrg-hash-to-curve-16`][hash_to_field].
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-expand_message_xmd
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L89
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L63
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L139
    fn expand_message_xmd(
        &self,
        msg: Vec<AssignedValue<F>>,
        len_in_bytes: usize,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let range = self.hash_chip.range();
        let gate = range.gate();

        // constants
        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::one());

        // assign DST bytes & cache them
        let dst_len = ctx.load_constant(F::from(S::DST.len() as u64));
        let dst_prime = self
            .assigned_dst_with_len
            .borrow_mut()
            .get_or_insert_with(|| {
                S::DST
                    .iter()
                    .map(|&b| ctx.load_constant(F::from(b as u64)))
                    .chain(iter::once(dst_len))
                    .collect()
            })
            .clone();

        // padding and length strings
        let z_pad = Self::i2osp(0, HC::BLOCK_SIZE, |b| zero);
        let l_i_b_str = Self::i2osp(len_in_bytes as u128, 2, |b| ctx.load_constant(b));

        // compute blocks
        let ell = len_in_bytes.div_ceil(HC::DIGEST_SIZE);
        let mut b_vals = Vec::with_capacity(ell);
        let msg_prime = z_pad
            .into_iter()
            .chain(msg)
            .chain(l_i_b_str)
            .chain(iter::once(zero))
            .chain(dst_prime.clone());

        let b_0 = self
            .hash_chip
            .digest(msg_prime.into(), ctx, region)?
            .output_bytes;

        b_vals.insert(
            0,
            self.hash_chip
                .digest(
                    b_0.clone()
                        .into_iter()
                        .chain(iter::once(one))
                        .chain(dst_prime.clone())
                        .into(),
                    ctx,
                    region,
                )?
                .output_bytes,
        );

        for i in 1..ell {
            b_vals.insert(
                i,
                self.hash_chip
                    .digest(
                        Self::strxor(b_0, b_vals[i - 1], gate, ctx)
                            .into_iter()
                            .chain(iter::once(ctx.load_constant(F::from(i as u64 + 1))))
                            .chain(dst_prime.clone())
                            .into(),
                        ctx,
                        region,
                    )?
                    .output_bytes,
            );
        }

        let uniform_bytes = b_vals
            .into_iter()
            .flatten()
            .take(len_in_bytes)
            .collect_vec();

        Ok(uniform_bytes)
    }

    // Integer to Octet Stream (numberToBytesBE)
    fn i2osp(
        mut value: u128,
        length: usize,
        mut f: impl FnMut(F) -> AssignedValue<F>,
    ) -> Vec<AssignedValue<F>> {
        let mut octet_string = vec![0; length];
        for i in (0..length).rev() {
            octet_string[i] = value & 0xff;
            value >>= 8;
        }
        octet_string
            .into_iter()
            .map(|b| f(F::from(b as u64)))
            .collect()
    }

    pub fn strxor(
        a: impl IntoIterator<Item = AssignedValue<F>>,
        b: impl IntoIterator<Item = AssignedValue<F>>,
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
    ) -> Vec<AssignedValue<F>> {
        a.into_iter()
            .zip(b.into_iter())
            .map(|(a, b)| Self::bitwise_xor::<8>(a, b, gate, ctx))
            .collect()
    }

    pub fn bitwise_xor<const BITS: usize>(
        a: AssignedValue<F>,
        b: AssignedValue<F>,
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
    ) -> AssignedValue<F> {
        let one = ctx.load_constant(F::one());
        let two = ctx.load_constant(F::from(2u64));
        let mut a_bits = gate.num_to_bits(ctx, a, BITS);
        let mut b_bits = gate.num_to_bits(ctx, b, BITS);

        let xor_bits = a_bits
            .into_iter()
            .zip(b_bits.into_iter())
            .map(|(a, b)| gate.xor(ctx, a, b))
            .collect_vec();

        xor_bits
            .into_iter()
            .rev()
            .fold(ctx.load_zero(), |acc, bit| gate.mul_add(ctx, acc, two, bit))
    }
}

fn bigint_to_le_bytes<F: Field>(
    limbs: impl IntoIterator<Item = F>,
    limb_bits: usize,
    total_bytes: usize,
) -> Vec<u8> {
    let limb_bytes = limb_bits / 8;
    limbs
        .into_iter()
        .flat_map(|x| x.to_bytes_le()[..limb_bytes].to_vec())
        .take(total_bytes)
        .collect()
}

#[cfg(test)]
mod test {
    use std::vec;
    use std::{cell::RefCell, marker::PhantomData};

    use crate::gadget::crypto::Sha256Chip;
    use crate::sha256_circuit::Sha256CircuitConfig;
    use crate::table::SHA256Table;
    use crate::util::{Challenges, IntoWitness, SubCircuitConfig};

    use super::*;
    use eth_types::Test;
    use halo2_base::gates::range::RangeConfig;
    use halo2_base::safe_types::RangeChip;
    use halo2_base::SKIP_FIRST_PASS;
    use halo2_base::{
        gates::{builder::GateThreadBuilder, range::RangeStrategy},
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::{Circuit, ConstraintSystem},
        },
    };
    use halo2_ecc::bigint::CRTInteger;
    use halo2curves::bls12_381;
    use sha2::{Digest, Sha256};

    #[derive(Debug, Clone)]
    struct TestConfig<F: Field> {
        sha256_config: Sha256CircuitConfig<F>,
        pub max_byte_size: usize,
        range: RangeConfig<F>,
        challenges: Challenges<F>,
    }

    struct TestCircuit<S: Spec, F: Field> {
        builder: RefCell<GateThreadBuilder<F>>,
        range: RangeChip<F>,
        test_input: HashInput<QuantumCell<F>>,
        _spec: PhantomData<S>,
    }

    impl<S: Spec, F: Field> Circuit<F> for TestCircuit<S, F> {
        type Config = TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha_table = SHA256Table::construct(meta);
            let sha256_configs = Sha256CircuitConfig::<F>::new::<Test>(meta, sha_table);
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                &[Self::NUM_ADVICE],
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );
            let challenges = Challenges::construct(meta);
            Self::Config {
                sha256_config: sha256_configs,
                max_byte_size: Self::MAX_BYTE_SIZE,
                range,
                challenges,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range.load_lookup_table(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            let sha256 = Sha256Chip::new(
                &config.sha256_config,
                &self.range,
                config.max_byte_size,
                config.challenges.sha256_input(),
                None,
                0,
            );

            let h2c_chip = HashToCurveChip::<Test, F, _>::new(sha256);
            let fp_chip = halo2_ecc::fields::fp::FpChip::<F, bls12_381::Fq>::new(
                &self.range,
                S::LIMB_BITS,
                S::NUM_LIMBS,
            );

            layouter.assign_region(
                || "hash to curve test",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    config.sha256_config.annotate_columns_in_region(&mut region);

                    let builder = &mut self.builder.borrow_mut();
                    let ctx = builder.main(0);

                    let [x, y] = h2c_chip.hash_to_field(
                        self.test_input.clone(),
                        &fp_chip,
                        ctx,
                        &mut region,
                    )?;

                    let extra_assignments = h2c_chip.hash_chip.take_extra_assignments();

                    let _ = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        extra_assignments,
                    );

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    impl<S: Spec, F: Field> TestCircuit<S, F> {
        const MAX_BYTE_SIZE: usize = 160;
        const NUM_ADVICE: usize = 20;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 12;
    }

    #[test]
    fn test_hash_to_g2() {
        let k = TestCircuit::<Test, Fr>::K as u32;

        let test_input = vec![0u8; 32];
        let range = RangeChip::default(TestCircuit::<Test, Fr>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        let circuit = TestCircuit::<Test, Fr> {
            builder: RefCell::new(builder),
            range,
            test_input: test_input.into_witness(),
            _spec: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
