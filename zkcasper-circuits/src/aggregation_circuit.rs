use crate::{
    table::{LookupTable, ValidatorsTable},
    util::{decode_into_field, Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, Committee, Validator},
};
use eth_types::{Spec, *};
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
    bigint::{ProperCrtUint, ProperUint},
    bn254::FpPoint,
    ecc::{EcPoint, EccChip},
    fields::FieldChip,
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::{
    bn256::{Fq, G1Affine},
    group::{ff::PrimeField, GroupEncoding, UncompressedEncoding},
};
use itertools::Itertools;
use num_bigint::BigUint;
use rayon::prelude::*;
use std::{
    cell::{RefCell, RefMut},
    marker::PhantomData,
};

// TODO: Use halo2_ccc::bls12_381::FpChip after carry mod issue is resolved in halo2-lib.
// for details see: https://github.com/flyingnobita/halo2-lib-no-fork/blob/bls12-381/halo2-ecc/src/bls12_381/notes.md
pub type FpChip<'range, F> = halo2_ecc::fields::fp::FpChip<'range, F, halo2curves::bn256::Fq>;

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

    fn new<S: Spec>(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
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
pub struct AggregationCircuitBuilder<'a, F: Field, S: Spec + Sync> {
    builder: RefCell<GateThreadBuilder<F>>,
    range: &'a RangeChip<F>,
    fp_chip: FpChip<'a, F>,
    // Witness
    validators: &'a [Validator],
    _committees: &'a [Committee],
    validators_y: Vec<Fq>,
    _spec: PhantomData<S>,
}

impl<'a, F: Field, S: Spec + Sync> AggregationCircuitBuilder<'a, F, S> {
    pub fn new(
        builder: GateThreadBuilder<F>,
        validators: &'a [Validator],
        committees: &'a [Committee],
        range: &'a RangeChip<F>,
    ) -> Self {
        let fp_chip = FpChip::new(range, S::LIMB_BITS, S::NUM_LIMBS);
        // TODO: Cache this in Validator witness type
        let validators_y = validators
            .iter()
            .map(|v| {
                let g1_affine =
                    G1Affine::from_bytes(&v.pubkey[..S::G1_BYTES_COMPRESSED].try_into().unwrap())
                        .unwrap();
                g1_affine.y
            })
            .collect();
        Self {
            builder: RefCell::new(builder),
            range,
            fp_chip,
            validators,
            _committees: committees,
            validators_y,
            _spec: PhantomData,
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
                    let mut pubkeys_compressed = vec![];
                    let _aggregated_pubkeys =
                        self.process_validators(builder, &mut pubkeys_compressed);

                    let ctx = builder.main(1);

                    let randomness = QuantumCell::Constant(
                        halo2_base::utils::value_to_option(challenges.sha256_input()).unwrap(),
                    );

                    let pubkey_rlcs = pubkeys_compressed
                        .into_iter()
                        .map(|compressed| {
                            self.get_rlc(&compressed[..S::G1_BYTES_COMPRESSED], &randomness, ctx)
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

    // TODO: Change to +4 when we switch to BLS12-381
    // Calculates y^2 = x^3 + 3 (the curve equation for bn254)
    fn calculate_ysquared(
        ctx: &mut Context<F>,
        field_chip: &FpChip<'_, F>,
        x: ProperCrtUint<F>,
    ) -> ProperCrtUint<F> {
        let x_squared = field_chip.mul(ctx, x.clone(), x.clone());
        let x_cubed = field_chip.mul(ctx, x_squared, x);

        let plus_b = field_chip.add_constant_no_carry(ctx, x_cubed, 3.into());
        field_chip.carry_mod(ctx, plus_b)
    }

    fn process_validators(
        &self,
        builder: &mut RefMut<GateThreadBuilder<F>>,
        pubkeys_compressed: &mut Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<EcPoint<F, FpPoint<F>>> {
        let ctx = builder.main(0);
        let range = self.range();
        let gate = range.gate();

        let fp_chip = self.fp_chip();
        let g1_chip = self.g1_chip();

        let grouped_validators = self
            .validators
            .iter()
            .zip(self.validators_y.iter())
            .group_by(|v| v.0.committee);
        // convert the `itertools::GroupBy` into a plain vector so that `rayon::par_iter`
        // can use it.
        let grouped_validators: Vec<Vec<(&Validator, &Fq)>> = grouped_validators
            .into_iter()
            .map(|(_committee, validator_coord_group)| {
                // NOTE: This needs to be a plain vector instead of the `Group` object that
                // isn't ParIter.
                validator_coord_group.into_iter().collect()
            })
            .collect();

        // NOTE: We convert the grouped validators into Rayon-provided `ParIter` so that we can use
        // parallel threads. But because of this, we can't use &mut self or any other mutable
        // types, so instead we return a vector of tuples from this `.map`, which we process later.
        type ParallelizedOutput<F> = (
            EcPoint<F, FpPoint<F>>,
            Context<F>,
            Vec<Vec<AssignedValue<F>>>,
        );
        let result: Vec<ParallelizedOutput<F>> = grouped_validators
            .into_par_iter()
            .map(|validators| {
                // TODO: Nothing within here can take `&mut self`.
                let mut in_committee_pubkeys = vec![];
                let mut ctx_clone = ctx.clone();
                let mut pubkeys_compressed_thread: Vec<Vec<AssignedValue<F>>> = vec![];

                for (validator, y_coord) in validators.into_iter() {
                    let pk_compressed = validator.pubkey[..S::G1_BYTES_COMPRESSED].to_vec();

                    let assigned_x_compressed_bytes: Vec<AssignedValue<F>> = ctx_clone
                        .assign_witnesses(pk_compressed.iter().map(|&b| F::from(b as u64)));

                    // assertion check for assigned_uncompressed vector to be equal to S::G1_BYTES_UNCOMPRESSED from specification
                    assert_eq!(assigned_x_compressed_bytes.len(), S::G1_BYTES_COMPRESSED);
                    // Clear the sign bit from the last byte of the compressed representation to construct the x coordinate in Fq
                    let mut pk_compressed_cleared = pk_compressed;
                    pk_compressed_cleared[S::G1_BYTES_COMPRESSED - 1] &= 0b0011_1111;
                    let x_coord =
                        Fq::from_bytes(&pk_compressed_cleared.as_slice().try_into().unwrap())
                            .unwrap();

                    // masked byte from compressed representation
                    let masked_byte = &assigned_x_compressed_bytes[S::G1_BYTES_COMPRESSED - 1];
                    // clear the sign bit from masked byte
                    let cleared_byte = Self::clear_ysign_mask(range, masked_byte, &mut ctx_clone);
                    // Use the cleared byte to construct the x coordinate
                    let assigned_x_bytes_cleared = [
                        &assigned_x_compressed_bytes.as_slice()[..S::G1_BYTES_COMPRESSED - 1],
                        &[cleared_byte],
                    ]
                    .concat();
                    let x_crt = decode_into_field::<S, F>(
                        assigned_x_bytes_cleared,
                        &fp_chip.limb_bases,
                        gate,
                        &mut ctx_clone,
                    );

                    // Load private witness y coordinate
                    let y_crt = fp_chip.load_private(&mut ctx_clone, *y_coord);
                    // Square y coordinate
                    let ysq = fp_chip.mul(&mut ctx_clone, y_crt.clone(), y_crt.clone());
                    // Calculate y^2 using the elliptic curve equation
                    let ysq_calc = Self::calculate_ysquared(&mut ctx_clone, fp_chip, x_crt.clone());
                    // Constrain witness y^2 to be equal to calculated y^2
                    fp_chip.assert_equal(&mut ctx_clone, ysq, ysq_calc);

                    // constraint that the loaded masked byte is consistent with the assigned bytes used to construct the point.
                    // ctx.constrain_equal(&cleared_byte, &assigned_x_bytes[S::G1_BYTES_COMPRESSED - 1]);

                    // cache assigned compressed pubkey bytes where each byte is constrainted with pubkey point.
                    // push this to the returnable and then use that
                    pubkeys_compressed_thread.push(assigned_x_compressed_bytes);
                    // Normally, we would need to take into account the sign of the y coordinate, but
                    // because we are concerned only with signature forgery, if this is the wrong
                    // sign, the signature will be invalid anyway and thus verification fails.
                    in_committee_pubkeys.push(EcPoint::new(x_crt, y_crt));
                }

                // let pk_affine = G1Affine::random(&mut rand::thread_rng());
                (
                    g1_chip.sum::<G1Affine>(&mut ctx_clone, in_committee_pubkeys),
                    ctx_clone,
                    pubkeys_compressed_thread,
                )
            })
            .collect();
        let mut aggregated_pubkeys = vec![];
        for (aggregated_pubkey, context, pubkeys_compressed_thread) in result.iter() {
            aggregated_pubkeys.push(aggregated_pubkey.clone());
            builder.threads[0].push(context.clone());
            for item in pubkeys_compressed_thread {
                pubkeys_compressed.push(item.clone());
            }
        }

        return aggregated_pubkeys;
    }

    /// Calculates RLCs (1 for each of two chacks of BLS12-381) for compresed bytes of pubkey.
    /// The resulted bigints should be equal to one used validators table.
    pub fn get_rlc(
        &self,
        assigned_bytes: &[AssignedValue<F>],
        randomness: &QuantumCell<F>,
        ctx: &mut Context<F>,
    ) -> [AssignedValue<F>; 2] {
        let gate = self.range().gate();
        // assertion check for assigned_bytes to be equal to S::G1_FQ_BYTES from specification
        assert_eq!(assigned_bytes.len(), S::G1_BYTES_COMPRESSED);

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
    fn clear_ysign_mask(
        range: &impl RangeInstructions<F>,
        b: &AssignedValue<F>,
        ctx: &mut Context<F>,
    ) -> AssignedValue<F> {
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

impl<'a, F: Field, S: Spec + Sync> SubCircuit<F> for AggregationCircuitBuilder<'a, F, S> {
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
    use eth_types::Test as S;
    use halo2_base::gates::range::RangeStrategy;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Debug, Clone)]
    struct TestCircuit<'a, F: Field, S: Spec + Sync> {
        inner: AggregationCircuitBuilder<'a, F, S>,
    }

    impl<'a, F: Field, S: Spec + Sync> TestCircuit<'a, F, S> {
        const NUM_ADVICE: &[usize] = &[6, 1];
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 1;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 14;
    }

    impl<'a, F: Field, S: Spec + Sync> Circuit<F> for TestCircuit<'a, F, S> {
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
            let config = AggregationCircuitConfig::new::<S>(
                meta,
                AggregationCircuitArgs {
                    validators_table,
                    range,
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
        let k = TestCircuit::<Fr, S>::K;
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let committees: Vec<Committee> =
            serde_json::from_slice(&fs::read("../test_data/committees.json").unwrap()).unwrap();

        let range = RangeChip::default(TestCircuit::<Fr, S>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        builder.config(k, None);
        let circuit = TestCircuit::<'_, Fr, S> {
            inner: AggregationCircuitBuilder::new(builder, &validators, &committees, &range),
        };

        let prover = MockProver::<Fr>::run(k as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
