mod witness_gen;

use crate::{
    table::{LookupTable, ValidatorsTable},
    util::{Challenges, SubCircuit, SubCircuitConfig, BaseConstraintBuilder},
    witness::{self, into_casper_entities, CasperEntity, Committee, Validator},
};
use eth_types::*;
use halo2_base::gates::range::RangeConfig;
use halo2_base::utils::CurveAffineExt;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Fixed}, poly::Rotation,
};
use halo2curves::group::{Curve, Group, UncompressedEncoding};
use std::marker::PhantomData;

use self::witness_gen::{aggregate_pubkeys, AggregationRow};

const G1_FQ_BYTES: usize = 32; // TODO: 48 for BLS12-381.
const G1_BYTES_UNCOMPRESSED: usize = G1_FQ_BYTES * 2;
const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;
const MAX_DEGREE: usize = 5;

#[derive(Clone, Debug)]
pub struct AggregationCircuitConfig<F: Field, C: Curve> {
    q_enabled: Column<Fixed>,
    validators_table: ValidatorsTable,
    range: RangeConfig<F>,
    pubkey_bytes: [Column<Advice>; G1_BYTES_UNCOMPRESSED],
    x_limbs: [Column<Advice>; NUM_LIMBS],
    y_limbs: [Column<Advice>; NUM_LIMBS],
    _curve: PhantomData<C>,
}

pub struct AggregationCircuitArgs<F: Field> {
    pub validators_table: ValidatorsTable,
    pub range: RangeConfig<F>,
}

impl<F: Field, C: Curve<AffineRepr: UncompressedEncoding>> SubCircuitConfig<F>
    for AggregationCircuitConfig<F, C>
{
    type ConfigArgs = AggregationCircuitArgs<F>;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let q_enabled = meta.fixed_column();
        let validators_table = args.validators_table;
        let range = args.range;
        let pubkey_bytes = array_init::array_init(|_| meta.advice_column());
        let x_limbs = array_init::array_init(|_| meta.advice_column());
        let y_limbs = array_init::array_init(|_| meta.advice_column());

        meta.create_gate("uncompressed to g1", |meta|{
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_enabled = meta.query_fixed(q_enabled, Rotation::cur());
            
            
            cb.gate(q_enabled)
        });

        Self {
            q_enabled,
            validators_table,
            range,
            pubkey_bytes,
            x_limbs,
            y_limbs,
            _curve: PhantomData,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.validators_table.annotate_columns_in_region(region);
        self.annotations()
            .into_iter()
            .for_each(|(col, ann)| region.name_column(|| &ann, col));
    }
}

impl<F: Field, C: Curve<AffineRepr: UncompressedEncoding>> AggregationCircuitConfig<F, C> {
    fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        validators: &[Validator],
        committees: &[Committee],
        _randomness: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities(validators.into_iter(), committees.into_iter());

        for (i, entity) in casper_entities.iter().enumerate() {
            // TODO: enable selector to max_rows
            region.assign_fixed(
                || "assign q_enabled",
                self.q_enabled,
                i,
                || Value::known(F::one()),
            )?;

            match entity {
                CasperEntity::Validator(validator) => {
                    let _pk_compressed = validator.pubkey[..G1_FQ_BYTES].to_vec();
                    let pk_affine = C::random(&mut rand::thread_rng()).to_affine();
                    let pk_uncompressed = pk_affine.to_uncompressed();
                    self.assign_row(
                        region,
                        i,
                        aggregate_pubkeys::<F>(pk_uncompressed.as_ref()),
                    )?;
                }
                CasperEntity::Committee(_) => {}
            }
        }

        // annotate circuit
        self.annotate_columns_in_region(region);

        Ok(())
    }

    pub fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: AggregationRow<F>,
    ) -> Result<(), Error> {
        for (&col, &byte) in self.pubkey_bytes.iter().zip(&row.pk_uncompressed) {
            region.assign_advice(
                || "assign uncompressed pubkey byte",
                col,
                offset,
                || Value::known(byte),
            )?;
        }

        for (&col, &limb) in self.x_limbs.iter().zip(&row.x_limbs) {
            region.assign_advice(
                || "assign pk_x limb",
                col,
                offset,
                || Value::known(limb),
            )?;
        }

        for (&col, &limb) in self.y_limbs.iter().zip(&row.y_limbs) {
            region.assign_advice(
                || "assign pk_y limb",
                col,
                offset,
                || Value::known(limb),
            )?;
        }

        Ok(())
    }

    pub fn annotations(&self) -> Vec<(Column<Any>, String)> {
        vec![(self.q_enabled.into(), "q_enabled".to_string())]
    }
}

#[derive(Default, Clone, Debug)]
pub struct AggregationCircuit<'a, F: Field, C: Curve> {
    validators: &'a [Validator],
    committees: &'a [Committee],
    _curve: PhantomData<C>,
    _field: PhantomData<F>,
}

impl<'a, F: Field, C: Curve> AggregationCircuit<'a, F, C> {
    pub fn new(validators: &'a [Validator], committees: &'a [Committee]) -> Self {
        Self {
            validators,
            committees,
            _field: PhantomData,
            _curve: PhantomData,
        }
    }
}

impl<'a, F: Field, C: Curve<AffineRepr: UncompressedEncoding>> SubCircuit<F>
    for AggregationCircuit<'a, F, C>
{
    type Config = AggregationCircuitConfig<F, C>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
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
        layouter.assign_region(
            || "aggregation circuit",
            |mut region| {
                config.assign_with_region(
                    &mut region,
                    self.validators,
                    self.committees,
                    challenges.sha256_input(),
                )?;
                Ok(())
            },
        )
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
    use halo2curves::{
        bn256::G1,
        group::{Curve, Group, UncompressedEncoding},
    };

    #[derive(Default, Debug, Clone)]
    struct TestCircuit<'a, F: Field, C: Curve> {
        inner: AggregationCircuit<'a, F, C>,
        _f: PhantomData<F>,
    }

    impl<'a, F: Field, C: Curve> TestCircuit<'a, F, C> {
        const NUM_ADVICE: usize = 50;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 12;
        const NUM_COMP: usize = 10;
        const K: usize = 13;
    }

    impl<'a, F: Field, C: Curve<AffineRepr: UncompressedEncoding>> Circuit<F>
        for TestCircuit<'a, F, C>
    {
        type Config = (AggregationCircuitConfig<F, C>, Challenges<F>);
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
                self.inner.committees,
                challenge,
            )?;
            self.inner
                .synthesize_sub(&config.0, &config.1.values(&mut layouter), &mut layouter)?;
            Ok(())
        }
    }

    #[test]
    fn test_aggregation_circuit() {
        let k = 10;
        let validators: Vec<Validator> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let committees: Vec<Committee> =
            serde_json::from_slice(&fs::read("../test_data/committees.json").unwrap()).unwrap();

        let circuit = TestCircuit::<'_, Fr, G1> {
            inner: AggregationCircuit::new(&validators, &committees),
            _f: PhantomData,
        };
        // let g1 = G1::random(&mut rand::thread_rng());
        // let g1_affine = g1.to_affine();
        // let b = g1_affine.to_uncompressed();
        // println!("b: {:?}", b);
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
