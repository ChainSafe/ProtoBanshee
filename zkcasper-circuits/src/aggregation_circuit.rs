use crate::{
    table::{LookupTable, ValidatorsTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, Committee, Validator},
};
use eth_types::*;
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
use std::{cell::RefCell, mem};

// pub type FpChip<'range, F> = halo2_ecc::bls12_381::FpChip<'range, F>;
pub type FpChip<'range, F> = halo2_ecc::fields::fp::FpChip<'range, F, halo2curves::bn256::Fq>;

const G1_FQ_BYTES: usize = 32; // TODO: 48 for BLS12-381.
const G1_BYTES_UNCOMPRESSED: usize = G1_FQ_BYTES * 2;
const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;

const PHASE: usize = 0;

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

    fn new(_meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
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
        Self {
            builder: RefCell::new(builder),
            range,
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
                    let ctx = builder.main(PHASE);
                    self.process_validators(challenges, ctx);

                    let threads = mem::take(&mut builder.threads[PHASE]);

                    halo2_base::gates::builder::assign_threads_in(
                        PHASE,
                        threads,
                        &config.range.gate,
                        &config.range.lookup_advice[PHASE],
                        &mut region,
                        vec![],
                    );
                    Ok(())
                },
            )
            .unwrap();
    }

    fn process_validators(&self, _challenges: &Challenges<F, Value<F>>, ctx: &mut Context<F>) {
        let range = self.range();

        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMBS);
        let g1_chip = EccChip::new(&fp_chip);

        for (_committee, validators) in self
            .validators
            .into_iter()
            .group_by(|v| v.committee)
            .into_iter()
        {
            let mut committee_pubkeys = Vec::new();
            for validator in validators {
                let pk_compressed = validator.pubkey[..G1_FQ_BYTES].to_vec();
                let pk_affine =
                    G1Affine::from_bytes(&pk_compressed.as_slice().try_into().unwrap()).unwrap();

                let assigned_bytes = ctx
                    .assign_witnesses(
                        pk_affine
                            .to_uncompressed()
                            .as_ref()
                            .iter()
                            .map(|&b| F::from(b as u64)),
                    )
                    .try_into()
                    .unwrap();

                committee_pubkeys.push(self.uncompressed_to_g1affine(
                    assigned_bytes,
                    &pk_affine,
                    ctx,
                ));
            }

            // let pk_affine = G1Affine::random(&mut rand::thread_rng());
            let _agg_pubkey = g1_chip.sum::<G1Affine>(ctx, committee_pubkeys);
        }
    }

    pub fn get_rlc<I: IntoIterator<Item = AssignedValue<F>>>(
        &self,
        assigned_bytes: I,
        randomness: Value<F>,
        ctx: &mut Context<F>,
    ) -> AssignedValue<F> {
        let gate = self.range().gate();

        let r = QuantumCell::Constant(halo2_base::utils::value_to_option(randomness).unwrap());

        assigned_bytes
            .into_iter()
            .fold(ctx.load_zero(), |acc, value| {
                gate.mul_add(ctx, acc, r, value)
            })
    }

    pub fn uncompressed_to_g1affine(
        &self,
        assigned_bytes: [AssignedValue<F>; G1_BYTES_UNCOMPRESSED],
        pk_affine: &G1Affine,
        ctx: &mut Context<F>,
    ) -> EcPoint<F, FpPoint<F>> {
        let range = self.range();
        let gate = range.gate();

        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMBS);

        let two = F::from(2);
        let f256 = ctx.load_constant(two.pow_const(8));

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
        config: &Self::Config,
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

    #[derive(Debug, Clone)]
    struct TestCircuit<'a, F: Field> {
        inner: AggregationCircuitBuilder<'a, F>,
    }

    impl<'a, F: Field> TestCircuit<'a, F> {
        const NUM_ADVICE: usize = 6;
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
                &[Self::NUM_ADVICE],
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
            );

            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            config.0.validators_table.dev_load(
                &mut layouter,
                self.inner.validators,
                self.inner._committees,
                challenge,
            )?;
            self.inner
                .synthesize_sub(&config.0, &config.1.values(&mut layouter), &mut layouter)?;
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
