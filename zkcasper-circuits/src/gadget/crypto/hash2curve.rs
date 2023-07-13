//! The chip that implements `draft-irtf-cfrg-hash-to-curve-16`
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use std::{cell::RefCell, iter, marker::PhantomData};

use eth_types::{Field, Spec};
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions, SafeBytes32, SafeTypeChip},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bn254::{FpChip, FqPoint},
    fields::vector::FieldVector,
};
use halo2_proofs::{circuit::Region, plonk::Error};
use itertools::Itertools;
use lazy_static::lazy_static;

use crate::{util::decode_into_field, witness::HashInput};

use super::sha256::HashChip;

const G2_EXT_DEGREE: usize = 2;

// L = ceil((ceil(log2(p)) + k) / 8) (see section 5 of ietf draft link above)
const L: usize = 64;

type Fp2Point<F> = FqPoint<F>;

#[derive(Debug)]
pub struct HashToCurveChip<S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: HC,
    assigned_dst_with_len: RefCell<Option<Vec<AssignedValue<F>>>>,
    binary_bases: RefCell<Option<Vec<AssignedValue<F>>>>,
    _s: PhantomData<S>,
}

impl<S: Spec, F: Field, HC: HashChip<F>> HashToCurveChip<S, F, HC> {
    pub fn new(hash_chip: HC) -> Self {
        Self {
            hash_chip,
            assigned_dst_with_len: Default::default(),
            binary_bases: Default::default(),
            _s: PhantomData,
        }
    }

    pub fn hash_to_field(
        &self,
        msg: HashInput<QuantumCell<F>>,
        fp_chip: &FpChip<F>,
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
                .map(|base| ctx.load_constant(F::from(base)))
                .collect()
        });

        let u = extended_msg
            .chunks(L)
            .chunks(G2_EXT_DEGREE)
            .into_iter()
            .map(|elm_chunk| {
                FieldVector(
                    elm_chunk
                        .map(|tv| {
                            decode_into_field::<S, F>(tv.to_vec(), &fp_chip.limb_bases, gate, ctx)
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
    /// Spec: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-expand_message_xmd
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
        let l_i_b_str = Self::i2osp(len_in_bytes, 2, |b| ctx.load_constant(b));

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

        b_vals[0] = self
            .hash_chip
            .digest(
                b_0.clone()
                    .into_iter()
                    .chain(iter::once(one))
                    .chain(dst_prime.clone())
                    .into(),
                ctx,
                region,
            )?
            .output_bytes;

        for i in 1..ell {
            b_vals[i] = self
                .hash_chip
                .digest(
                    Self::strxor(b_0, b_vals[i], gate, ctx)
                        .into_iter()
                        .chain(iter::once(ctx.load_constant(F::from(i as u64 + 1))))
                        .chain(dst_prime.clone())
                        .into(),
                    ctx,
                    region,
                )?
                .output_bytes;
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
        value: usize,
        len: usize,
        mut f: impl FnMut(F) -> AssignedValue<F>,
    ) -> Vec<AssignedValue<F>> {
        assert!(value < 1 << (8 * len));
        value
            .to_be_bytes()
            .iter()
            .map(|&b| f(F::from(b as u64)))
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
            .fold(ctx.load_zero(), |acc, bit| gate.mul_add(ctx, acc, two, bit))
    }
}

#[test]
fn test_hash_to_g2() {}
