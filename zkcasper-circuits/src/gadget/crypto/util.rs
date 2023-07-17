use super::hash2curve::HashToCurveCache;
use eth_types::{AppCurveExt, Field, HashCurveExt};
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::{fp::FpChip, vector::FieldVector, FieldChip, FieldExtConstructor, PrimeField},
};
use itertools::Itertools;
use num_bigint::BigUint;

pub type FpPoint<F> = ProperCrtUint<F>;
pub type Fp2Point<F> = FieldVector<FpPoint<F>>;
pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, Fp2Point<F>>;

#[allow(type_alias_bounds)]
pub type Fp2Chip<'chip, F, C: HashCurveExt> =
    halo2_ecc::fields::fp2::Fp2Chip<'chip, F, FpChip<'chip, F, C::Fp>, C::Fq>;
#[allow(type_alias_bounds)]
pub type EccChip<'chip, F, C: HashCurveExt> =
    halo2_ecc::ecc::EccChip<'chip, F, Fp2Chip<'chip, F, C>>;

pub fn fp2_sgn0<F: Field, C: AppCurveExt>(
    x: Fp2Point<F>,
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F, C::Fp>,
) -> AssignedValue<F> {
    let gate = fp_chip.gate();
    let c0 = x.0[0].clone();
    let c1 = x.0[1].clone();

    let c0_zero = fp_chip.is_zero(ctx, &c0);
    let c0_sgn = fp_sgn0::<F, C>(c0, ctx, fp_chip);
    let c1_sgn = fp_sgn0::<F, C>(c1, ctx, fp_chip);
    let sgn = gate.select(ctx, c1_sgn, c0_sgn, c0_zero);
    gate.assert_bit(ctx, sgn);
    sgn
}

pub fn fp_sgn0<F: Field, C: AppCurveExt>(
    x: FpPoint<F>,
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F, C::Fp>,
) -> AssignedValue<F> {
    let range = fp_chip.range();
    let gate = range.gate();

    let msl = x.limbs()[0]; // most significant limb

    let lsb = range
        .div_mod(ctx, msl, BigUint::from(256u64), C::LIMB_BITS)
        .1; // get least significant *byte*
    range.div_mod(ctx, lsb, BigUint::from(2u64), 8).1 // sgn0 = lsb % 2
}

/// Integer to Octet Stream (numberToBytesBE)
pub fn i2osp<F: Field>(
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

pub fn strxor<F: Field>(
    a: impl IntoIterator<Item = AssignedValue<F>>,
    b: impl IntoIterator<Item = AssignedValue<F>>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> Vec<AssignedValue<F>> {
    a.into_iter()
        .zip(b.into_iter())
        .map(|(a, b)| bitwise_xor::<_, 8>(a, b, gate, ctx))
        .collect()
}

pub fn bitwise_xor<F: Field, const BITS: usize>(
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


