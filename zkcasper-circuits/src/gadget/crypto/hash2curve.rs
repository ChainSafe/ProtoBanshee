//! The chip that implements `draft-irtf-cfrg-hash-to-curve-16`
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use std::{cell::RefCell, iter, marker::PhantomData, ops::Add};

use crate::{
    util::{decode_into_field, decode_into_field_be},
    witness::HashInput,
};
use eth_types::{AppCurveExt, Field, HashCurveExt, Spec};
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions, SafeBytes32, SafeTypeChip},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{CRTInteger, ProperUint},
    fields::{fp::FpChip, FieldChip, FieldExtConstructor, PrimeField, vector::FieldVector, Selectable},
};
use halo2_proofs::{circuit::Region, plonk::Error};
use halo2curves::group::GroupEncoding;
use itertools::Itertools;
use lazy_static::{__Deref, lazy_static};
use num_bigint::{BigInt, BigUint};
use pasta_curves::arithmetic::SqrtRatio;

use super::{sha256::HashChip, util::*};

const G2_EXT_DEGREE: usize = 2;

// L = ceil((ceil(log2(p)) + k) / 8) (see section 5 of ietf draft link above)
const L: usize = 64;

#[derive(Debug)]
pub struct HashToCurveChip<S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: HC,
    _f: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec, F: Field, HC: HashChip<F>> HashToCurveChip<S, F, HC> {
    pub fn new(hash_chip: HC) -> Self {
        Self {
            hash_chip,
            _f: PhantomData,
            _spec: PhantomData,
        }
    }

    /// Implements [section 5.2 of `draft-irtf-cfrg-hash-to-curve-16`][hash_to_field].
    ///
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.2
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L49
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L128
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L11
    pub fn hash_to_field<C: HashCurveExt>(
        &self,
        msg: HashInput<QuantumCell<F>>,
        fp_chip: &FpChip<F, C::Fp>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        cache: &mut HashToCurveCache<F>,
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
        let extended_msg =
            self.expand_message_xmd(assigned_msg, len_in_bytes, ctx, region, cache)?;

        let limb_bases = cache.binary_bases.get_or_insert_with(|| {
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

                            let lo_2_256 =
                                fp_chip.mul_no_carry(ctx, lo.clone(), two_pow_256.clone());
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

    pub fn map_to_curve<C: HashCurveExt>(
        &self,
        u: [Fp2Point<F>; 2],
        fp_chip: &FpChip<F, C::Fp>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> Result<(), Error>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let fp2_chip = Fp2Chip::<_, C>::new(fp_chip);
        let curve_chip = EccChip::<F, C>::new(&fp2_chip);

        let [u0, u1] = u;

        let p1 = Self::map_to_curve_simple_swu::<C>(u0, &fp2_chip, ctx, cache);
        let p2 = Self::map_to_curve_simple_swu::<C>(u1, &fp2_chip, ctx, cache);

        let p_sum = curve_chip.add_unequal(ctx, p1, p2, false);

        Ok(())
    }

    /// Implements [section 5.3 of `draft-irtf-cfrg-hash-to-curve-16`][expand_message_xmd].
    ///
    /// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3
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
        cache: &mut HashToCurveCache<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let range = self.hash_chip.range();
        let gate = range.gate();

        // constants
        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::one());

        // assign DST bytes & cache them
        let dst_len = ctx.load_constant(F::from(S::DST.len() as u64));
        let dst_prime = cache
            .dst_with_len
            .get_or_insert_with(|| {
                S::DST
                    .iter()
                    .map(|&b| ctx.load_constant(F::from(b as u64)))
                    .chain(iter::once(dst_len))
                    .collect()
            })
            .clone();

        // padding and length strings
        let z_pad = i2osp(0, HC::BLOCK_SIZE, |b| zero); // TODO: cache these
        let l_i_b_str = i2osp(len_in_bytes as u128, 2, |b| ctx.load_constant(b));

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
                        strxor(b_0, b_vals[i - 1], gate, ctx)
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

    /// Implements [section 6.2 of draft-irtf-cfrg-hash-to-curve-16][map_to_curve_simple_swu]
    ///
    /// [map_to_curve_simple_swu]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.1-3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/hash_to_curve/map_g2.rs#L388
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/weierstrass.ts#L1175
    fn map_to_curve_simple_swu<C: HashCurveExt>(
        u: Fp2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let fp_chip = fp2_chip.fp_chip();
        let gate = fp_chip.range().gate();

        // constants
        let swu_a = cache
            .swu_a
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_A)).deref().clone();
        let swu_b = cache
            .swu_b
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_B)).deref().clone();
        let swu_z = cache
            .swu_z
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_Z)).deref().clone();
        let fq2_one = cache
            .fq2_one
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::Fq::one())).deref().clone();

        let usq = fp2_chip.mul(ctx, u.clone(), u.clone()); // 1.  tv1 = u^2
        let z_usq = fp2_chip.mul(ctx, usq.clone(), swu_z.clone()); // 2.  tv1 = Z * tv1
        let zsq_u4 = fp2_chip.mul(ctx, z_usq.clone(), z_usq.clone()); // 3.  tv2 = tv1^2
        let tv2 = fp2_chip.add_no_carry(ctx, zsq_u4.clone(), z_usq.clone()); // 4.  tv2 = tv2 + tv1
        let tv3 = fp2_chip.add_no_carry(ctx, zsq_u4.clone(), fq2_one.clone()); // 5.  tv3 = tv2 + 1
        let x0_num = fp2_chip.mul(ctx, tv3.clone(), swu_b.clone()); // 6.  tv3 = B * tv3

        let x_den = {
            let tv2 = fp2_chip.carry_mod(ctx, tv2);
            let tv2_is_zero = fp2_chip.is_zero(ctx, tv2.clone());
            let tv2_neg = fp2_chip.negate(ctx, tv2);

            fp2_chip.select(ctx, swu_z.clone(), tv2_neg, tv2_is_zero) // tv2_is_zero ? swu_z : tv2_neg
        }; // 7.  tv4 = tv2 != 0 ? -tv2 : Z

        let x_den = fp2_chip.mul(ctx, x_den, swu_a.clone()); // 8.  tv4 = A * tv4

        let x0_num_sqr = fp2_chip.mul(ctx, x0_num.clone(), x0_num.clone()); // 9.  tv2 = tv3^2
        let x_densq = fp2_chip.mul(ctx, x_den.clone(), x_den.clone()); // 10. tv6 = tv4^2
        let ax_densq = fp2_chip.mul(ctx, x_densq.clone(), swu_a.clone()); // 11. tv5 = A * tv6
        let tv2 = fp2_chip.add_no_carry(ctx, x0_num_sqr.clone(), ax_densq.clone()); // 12. tv2 = tv2 + tv5
        let tv2 = fp2_chip.mul(ctx, tv2, x0_num_sqr); // 13. tv2 = tv2 * tv3
        let gx_den = fp2_chip.mul(ctx, x_densq, x_den.clone()); // 14. tv6 = tv6 * tv4
        let tv5 = fp2_chip.mul(ctx, gx_den.clone(), swu_b.clone()); // 15. tv5 = B * tv6
        let gx0_num = {
            let tv2 = fp2_chip.add_no_carry(ctx, tv2, tv5);
            fp2_chip.carry_mod(ctx, tv2)
        }; // 16. tv2 = tv2 + tv5

        let x = fp2_chip.mul(ctx, &z_usq, &x0_num); // 17.  x = tv1 * tv3
        let (is_gx1_square, y1) = Self::sqrt_ratio::<C>(gx0_num, gx_den, &fp2_chip, ctx, cache); // 18.  (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
        let y = fp2_chip.mul(ctx, &z_usq, &u); // 19.  y = tv1 * u
        let y = fp2_chip.mul(ctx, y, y1.clone()); // 20.  y = y * y1
        let x = fp2_chip.select(ctx, x, x0_num, is_gx1_square); // 21.  x = is_gx1_square ? x : tv3
        let y = fp2_chip.select(ctx, y, y1, is_gx1_square); // 22.  y = is_gx1_square ? y : y1

        let to_neg = {
            let u_sgn = fp2_sgn0::<_, C>(u, ctx, fp_chip);
            let y_sgn = fp2_sgn0::<_, C>(y.clone(), ctx, fp_chip);
            gate.xor(ctx, u_sgn, y_sgn)
        }; // 23.  e1 = sgn0(u) == sgn0(y)

        let y_neg = fp2_chip.negate(ctx, y.clone());
        let y = fp2_chip.select(ctx, y_neg, y, to_neg); // 24.  y = e1 ? -y : y
        let x = fp2_chip.divide(ctx, x, x_den); // 25.  x = x / tv4

        G2Point::new(x, y)
    }

    /// Implements [Appendix E.3 of draft-irtf-cfrg-hash-to-curve-16][isogeny_map_g2]
    ///
    /// [isogeny_map_g2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-E.3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/g2.rs#L1153
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L167
    pub fn isogeny_map_g2<C: HashCurveExt>(
        &self,
        p: &G2Point<F>,
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        // constants
        let iso_coeffs = cache
            .iso_coeffs
            .get_or_insert_with(|| {
                [
                    C::ISO_XNUM.to_vec(),
                    C::ISO_XDEN.to_vec(),
                    C::ISO_YNUM.to_vec(),
                    C::ISO_YDEN.to_vec(),
                ]
                .map(|coeffs| {
                    coeffs
                        .into_iter()
                        .map(|iso| fp2_chip.load_constant(ctx, iso))
                        .collect_vec()
                })
            })
            .deref()
            .clone();

        let fq2_zero = cache
            .fq2_zero
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::Fq::zero()))
            .deref()
            .clone();

        let [x_num, x_den, y_num, y_den] = iso_coeffs.clone().map(|coeffs| {
            coeffs.into_iter().fold(fq2_zero.clone(), |acc, v| {
                let acc = fp2_chip.mul(ctx, acc, &p.x);
                let no_carry = fp2_chip.add_no_carry(ctx, acc, v);
                fp2_chip.carry_mod(ctx, no_carry)
            })
        });

        let x = { fp2_chip.divide_unsafe(ctx, x_num, x_den) };

        let y = {
            let tv = fp2_chip.divide_unsafe(ctx, y_num, y_den);
            fp2_chip.mul(ctx, &p.y, tv)
        };

        G2Point::new(x, y)
    }

    /// Implements [Appendix G.3 of draft-irtf-cfrg-hash-to-curve-16][clear_cofactor]
    ///
    /// [clear_cofactor]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-G.3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/g2.rs#L956
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/bls12-381.ts#L1111
    pub fn clear_cofactor<C: HashCurveExt>(
        &self,
        p: &G2Point<F>,
        ecc_chip: &EccChip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> G2Point<F>
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let x = C::BLS_X; // NOTE: in BLS12-381 we can just skip the first bit (BLS_X >> 1)

        // let t1 = {
        //     let tv = ecc_chip.(&p_g2, x, &mut ecc_ctx);
        //     g2_neg(&tv, &mut ecc_ctx)
        // }; // [-x]P

        p.clone()
    }

    // Implements [Appendix F.2.1 of draft-irtf-cfrg-hash-to-curve-16][sqrt_ration]
    //
    // [sqrt_ration]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.2.1
    fn sqrt_ratio<C: HashCurveExt>(
        num: Fp2Point<F>, // u
        div: Fp2Point<F>, // v
        fp2_chip: &Fp2Chip<F, C>,
        ctx: &mut Context<F>,
        cache: &mut HashToCurveCache<F>,
    ) -> (AssignedValue<F>, Fp2Point<F>)
    where
        C::Fq: FieldExtConstructor<C::Fp, 2>,
    {
        let num_v = C::get_fq(num.0.iter().map(|c| c.value()));
        let div_v = C::get_fq(div.0.iter().map(|c| c.value()));

        let (is_square, y) = C::Fq::sqrt_ratio(&num_v, &div_v);

        let is_square = ctx.load_witness(F::from(is_square.unwrap_u8() as u64));
        fp2_chip.fp_chip().gate().assert_bit(ctx, is_square); // assert is_square is boolean

        let y_assigned = fp2_chip.load_private(ctx, y);

        let num_div = fp2_chip.divide(ctx, num.clone(), div.clone()); // r (ratio) = u / v
        let num_div_sqr = fp2_chip.mul(ctx, num_div.clone(), num_div.clone()); // sqrt_a = r^2

        let rv1 = cache
            .swu_rv1
            .get_or_insert_with(|| fp2_chip.load_constant(ctx, C::SWU_RV1));
        let num_div_rv1 = fp2_chip.mul(ctx, num_div, rv1.clone()); // sqrt_b = r * rv1 (first root of unity)

        let y_check = fp2_chip.select(ctx, num_div_sqr, num_div_rv1, is_square.clone()); // y_check = is_square ? sqrt_a : sqrt_b

        fp2_chip.assert_equal(ctx, y_check, y_assigned.clone()); // assert y_check == y_assigned

        (is_square, y_assigned)
    }
}

#[derive(Clone, Debug, Default)]
pub struct HashToCurveCache<F: Field> {
    dst_with_len: Option<Vec<AssignedValue<F>>>,
    binary_bases: Option<Vec<AssignedValue<F>>>,
    swu_a: Option<Fp2Point<F>>,
    swu_b: Option<Fp2Point<F>>,
    swu_z: Option<Fp2Point<F>>,
    fq2_zero: Option<Fp2Point<F>>,
    fq2_one: Option<Fp2Point<F>>,
    swu_rv1: Option<Fp2Point<F>>,
    iso_coeffs: Option<[Vec<Fp2Point<F>>; 4]>,
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

                    let mut cache = HashToCurveCache::<F>::default();
                    let [x, y] = h2c_chip.hash_to_field::<bls12_381::G2>(
                        self.test_input.clone(),
                        &fp_chip,
                        ctx,
                        &mut region,
                        &mut cache,
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
