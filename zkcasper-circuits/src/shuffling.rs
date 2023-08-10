use std::{iter, marker::PhantomData, mem, ops::Mul};

use eth_types::{Field, Mainnet, Spec};
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    is_zero,
    util::{not, or, select, Expr},
};
use halo2_base::{
    gates::range,
    safe_types::{GateInstructions, RangeChip, RangeInstructions, SafeTypeChip},
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{self, Constant},
};
use halo2_proofs::{
    circuit::{layouter, AssignedCell, Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector, VirtualCells,
    },
    poly::Rotation,
};
use num_bigint::BigUint;
use sha2::Digest;

use crate::{
    gadget::{
        crypto::{AssignedHashResult, HashChip},
        math::IsZeroGadget,
    },
    sha256_circuit::Sha256CircuitConfig,
    table::{sha256_table, Sha256Table},
    // table::SHA256Table,
    util::{
        from_bytes, from_u64_bytes, BaseConstraintBuilder, ConstrainBuilderCommon, SubCircuitConfig,
    },
    witness::{HashInput, HashInputChunk},
};

const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

const U64_BITS: usize = 64;
const U64_BYTES: usize = U64_BITS / 8;
const U32_BITS: usize = 32;
const U32_BYTES: usize = U32_BITS / 8;

const EMPTY_HASH: [u8; 32] = [0; 32];
#[derive(Debug)]

pub struct ShuffleChip<'a, S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: &'a HC,
    _f: PhantomData<F>,
    _s: PhantomData<S>,
}

#[derive(Clone, Debug)]
pub struct ShufflingConfig<F: Field, const ROUNDS: usize> {
    pub seed: [Column<Advice>; 32], // Should be instance column, right?

    pub list_length: Column<Advice>,
    pub i: Column<Advice>, // plus one sequential
    pub list_items: Column<Advice>,
    pub q_enable: Selector,

    pub q_round_ops: Selector, // 90 Rows
    pub round: Column<Advice>, // 90 * (N/2) Rows
    pub hash: Column<Advice>, // 90 Rows. (hash = sha(seed, round))[0..8] is used to calculate pivot

    pub pivot: Column<Advice>,            // 90 Rows
    pub pivot_quotient: Column<Advice>,   // 90 Rows
    pub pivot_hash: [Column<Advice>; 32], // 90 * (N/2) Rows
    pub mirror1: Column<Advice>,          // 90 Rows
    pub mirror2: Column<Advice>,          // 90 Rows

    pub hash_bytes: [Column<Advice>; 32], // 90 * (N/2) Rows

    pub flip: Column<Advice>,               // 90 * (N/2) Rows
    pub bit_index: Column<Advice>,          // 90 * (N/2) Rows. In range [0, 255(0xff)]
    pub bit_index_quotient: Column<Advice>, // 90 * (N/2) Rows

    pub the_byte: Column<Advice>, // 90 * (N/2)
    pub the_bit: Column<Advice>,  // 90 * (N/2) u8
    // pub the_bit: [Column<Advice>; 8],  // 90 * (N/2) u8
    pub left_half: Selector,

    // Hashables
    pub seed_concat_round: Column<Advice>,          // 90 Rows
    pub seed_concat_round_concat_i: Column<Advice>, // 90 * (N/2) Rows

    pub is_zero_bit_index: Option<IsZeroGadget<F>>,
    pub is_zero_i_minus_mirror1: Option<IsZeroGadget<F>>,
    pub is_zero_i_minus_pivot_minus_1: Option<IsZeroGadget<F>>,
    pub is_zero_bit_index_minus_255: Option<IsZeroGadget<F>>,

    pub sha256_table: Sha256Table,
}

impl<const ROUNDS: usize, F: Field> ShufflingConfig<F, ROUNDS> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let sha256_table = Sha256Table::construct::<F>(meta);
        let seed = [(); 32].map(|_| meta.advice_column());
        let list_length = meta.advice_column();
        let i = meta.advice_column();
        let list_items = meta.advice_column();
        let round = meta.advice_column();
        let pivot = meta.advice_column();

        let mirror1 = meta.advice_column();
        let mirror2 = meta.advice_column();
        let flip = meta.advice_column();
        let bit_index = meta.advice_column();
        let the_byte = meta.advice_column();
        let the_bit = meta.advice_column();
        let bit_index_quotient = meta.advice_column();
        let hash = meta.advice_column();
        let seed_concat_round = meta.advice_column();
        let hash_bytes = [(); 32].map(|_| meta.advice_column());
        let seed_concat_round_concat_i = meta.advice_column();

        let left_half = meta.complex_selector();
        let q_enable = meta.selector();

        let pivot_hash = [(); 32].map(|_| meta.advice_column());
        let pivot_quotient = meta.advice_column();

        let q_round_ops = meta.selector();

        let mut config = Self {
            seed,
            list_length,
            i,
            list_items,
            round,
            pivot,
            mirror1,
            mirror2,
            flip,
            bit_index,
            the_byte,
            the_bit,
            bit_index_quotient,
            left_half,
            sha256_table,
            hash,
            hash_bytes,
            seed_concat_round,
            seed_concat_round_concat_i,
            q_enable,
            q_round_ops,
            is_zero_bit_index: None,
            is_zero_i_minus_mirror1: None,
            is_zero_i_minus_pivot_minus_1: None,
            is_zero_bit_index_minus_255: None,
            pivot_hash,
            pivot_quotient,
        };

        meta.create_gate("per round variables", |m| {
            let mut cb = BaseConstraintBuilder::default();
            let pivot = m.query_advice(pivot, Rotation::cur());
            let m1 = m.query_advice(mirror1, Rotation::cur());
            let m2 = m.query_advice(mirror2, Rotation::cur());
            let list_length = m.query_advice(list_length, Rotation::cur());
            let pivot_hash = pivot_hash.map(|c| m.query_advice(c, Rotation::cur()));
            let pivot_quotient = m.query_advice(pivot_quotient, Rotation::cur());
            let q_enable = m.query_selector(q_enable);
            // TODO: Restrict Pivot_bytes to be hash[0 ..8]
            // Is this overflowing???
            cb.require_equal(
                "pivot == u64_le(pivot_byte) % list_size",
                pivot_quotient * list_length.clone() + pivot.clone(),
                from_u64_bytes::expr(&pivot_hash[0..8]),
            );
            cb.require_in_set(
                "mirror m1 = (pivot + 2) / 2",
                pivot.clone() + 2u64.expr(),
                [m1.clone() * 2.expr(), m1 * 2.expr() + 1.expr()].to_vec(), // TODO: Is this safe to not properly check if even or odd?
            );
            cb.require_in_set(
                "mirror m2 = (pivot + list_length) / 2",
                pivot + list_length,
                [m2.clone() * 2.expr(), m2.clone() * 2.expr() + 1.expr()].to_vec(),
            );
            cb.gate(q_enable)
        });

        // // TODO: Enforce concat(seed, round) == seed_concat_round
        // meta.lookup_any("hash = sha256(seed, round) as byte", |meta| {
        //     // let seed_concat_round = meta.query_advice(seed_concat_round, Rotation::cur());
        //     // let q_round_ops = meta.query_selector(q_round_ops);
        //     let seed = seed.map(|s| meta.query_instance(s, Rotation::cur()));
        //     let round = meta.query_advice(round, Rotation::cur());
        //     let hash = meta.query_advice(hash, Rotation::cur());
        //     config
        //         .sha256_table
        //         .build_lookup(meta, q_round_ops, seed_concat_round, 0.expr(), hash)
        // });

        // // TODO: Enforce concat(seed, round, i) == seed_concat_round_concat_i
        // meta.lookup_any(
        //     "hash_bytes = sha256(seed, round_as_bytes, uintTo4Bytes(i or flip /256)",
        //     |meta| {
        //         let seed_concat_round_concat_i =
        //             meta.query_advice(seed_concat_round_concat_i, Rotation::cur());
        //         let hash_bytes = meta.query_advice(hash_bytes, Rotation::cur());

        //         config.sha256_table.build_lookup(
        //             meta,
        //             1.expr(),
        //             seed_concat_round_concat_i,
        //             0.expr(),
        //             hash_bytes,
        //         )
        //     },
        // );

        meta.create_gate("inner loop", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let flip = meta.query_advice(flip, Rotation::cur());
            let i = meta.query_advice(i, Rotation::cur());
            let pivot = meta.query_advice(pivot, Rotation::cur());
            let list_length = meta.query_advice(list_length, Rotation::cur());
            let bit_index = meta.query_advice(bit_index, Rotation::cur());
            let bit_index_quotient = meta.query_advice(bit_index_quotient, Rotation::cur());
            let mirror1 = meta.query_advice(mirror1, Rotation::cur());

            let q_enable = meta.query_selector(q_enable);
            let left_half = meta.query_selector(left_half);

            // let is_zero_bit_index = IsZeroGadget::construct(&mut cb, bit_index.clone());
            // let is_zero_bit_index_minus_255 =
            //     IsZeroGadget::construct(&mut cb, bit_index.clone() - 255.expr());
            // let is_zero_i_minus_mirror1 =
            //     IsZeroGadget::construct(&mut cb, i.clone() - mirror1.clone());
            // let is_zero_i_minus_pivot_minus_1 =
            //     IsZeroGadget::construct(&mut cb, i.clone() - pivot.clone() - 1.expr());

            cb.require_boolean("require left half be boolean", left_half.clone());
            cb.require_equal(
                "(left of pivot) flip = pivot - i",
                0.expr(),
                left_half.clone() * (flip.clone() - pivot.clone() + i.clone()),
            );
            cb.require_equal(
                "(right of pivot) flip = pivot + list size - i",
                0.expr(),
                not::expr(left_half.clone())
                    * (flip.clone() - (pivot.clone() + list_length.clone() - i.clone())),
            );
            let i_or_flip = select::expr(left_half.clone(), i.clone(), flip.clone());
            cb.require_equal(
                "bit_index = i & 0xff or flip & 0xff",
                bit_index_quotient.clone() * 256.expr(),
                i_or_flip - bit_index.clone(),
            );

            // config.is_zero_bit_index = Some(is_zero_bit_index);
            // config.is_zero_i_minus_mirror1 = Some(is_zero_i_minus_mirror1);
            // config.is_zero_i_minus_pivot_minus_1 = Some(is_zero_i_minus_pivot_minus_1);
            // config.is_zero_bit_index_minus_255 = Some(is_zero_bit_index_minus_255);

            cb.gate(q_enable)
        });

        // if is_left AND bit_index == 0 OR i == mirror1 -> Hash
        // else if NOT is_left AND bit_index == 255 OR i == pivot + 1 -> Hash
        // else -> No Hash

        // select::expr(
        //     is_left.clone(),
        //     select::expr(
        //         or::expr(
        //             [is_zero_bit_index.expr(), is_zero_i_minus_mirror1.expr()].into_iter(),
        //         ),
        //         1.expr(), // Do lookup table on new hash value
        //         0.expr(), // Hash stays the same
        //     ),
        //     select::expr(
        //         or::expr(
        //             [
        //                 is_zero_bit_index_minus_255.expr(),
        //                 is_zero_i_minus_pivot_minus_1.expr(),
        //             ]
        //             .into_iter(),
        //         ),
        //         2.expr(), // Do lookup table on new hash value
        //         0.expr(), // Hash stays the same
        //     ),
        // );

        println!("shuffling circuit degree={}", meta.degree());

        config
    }

    pub fn shuffle_list(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &mut [u8],
        seed: [u8; 32],
    ) -> Result<(), Error> {
        let list_size = input.len();
        if list_size == 0 {
            return Ok(());
        }

        let mut shuffle_row = vec![];

        for round in (0..90) {
            let round_as_byte: [u8; 1] = [round as u8];

            let pivot_hash =
                sha2::Sha256::digest(vec![seed.to_vec(), round_as_byte.to_vec()].concat());

            let pivot = u64::from_le_bytes(pivot_hash[0..8].try_into().expect("Expected 8 bytes"));
            println!(
                "pivot is: {:#X?}, pivotmod is {:#X?}, and pivot hash le: {:#X?}",
                pivot,
                pivot % list_size as u64,
                &pivot_hash[0..8]
            );
            let pivot_quotient = pivot / list_size as u64;
            let pivot = pivot % list_size as u64;

            let mut hash_bytes = EMPTY_HASH;
            let mirror1 = (pivot + 2) / 2;
            let mirror2 = (pivot + list_size as u64) / 2;

            for i in mirror1..=mirror2 {
                let (flip, bit_index, bit_index_quotient) = if i <= pivot {
                    let flip = pivot - i;
                    let bit_index = (i & 0xff) as usize;
                    let bit_index_quotient = (i / 256) as usize;

                    if bit_index == 0 || i == mirror1 {
                        hash_bytes = sha2::Sha256::digest(
                            vec![
                                seed.to_vec(),
                                round_as_byte.to_vec(),
                                (i / 256).to_le_bytes()[0..POSITION_WINDOW_SIZE].to_vec(),
                            ]
                            .concat(),
                        )
                        .try_into()
                        .unwrap();
                    }
                    (flip, bit_index, bit_index_quotient)
                } else {
                    let flip = pivot + list_size as u64 - i;
                    let bit_index = (flip & 0xff) as usize;
                    let bit_index_quotient = (flip / 256) as usize;
                    if bit_index == 0xff || i == pivot + 1 {
                        hash_bytes = sha2::Sha256::digest(
                            vec![
                                seed.to_vec(),
                                round_as_byte.to_vec(),
                                (flip / 256).to_le_bytes()[0..POSITION_WINDOW_SIZE].to_vec(),
                            ]
                            .concat(),
                        )
                        .try_into()
                        .unwrap();
                    }
                    (flip, bit_index, bit_index_quotient)
                };

                let the_byte = hash_bytes[bit_index / 8];
                let the_bit = (the_byte >> (bit_index & 0x07)) & 1;
                if the_bit != 0 {
                    input.swap(i as usize, flip as usize);
                }

                let offset = ((i - mirror1) + 1) as usize
                    + (round as u64 * (mirror2 - mirror1 + 1)) as usize
                    - 1;
                println!(
                    "is_left: {} Offset {} Round {} pivot {} mirror1 {} mirror2 {} flip {} bit_index {} bit_index_quotient {} the_byte {} the_bit {} i {}",
                    i<= pivot, offset, round, pivot, mirror1, mirror2, flip, bit_index, bit_index_quotient, the_byte, the_bit, i);

                let row = ShuffleRow {
                    offset,
                    list_size: list_size as u64,
                    pivot,
                    mirror1,
                    mirror2,
                    flip,
                    bit_index: bit_index.try_into().unwrap(),
                    bit_index_quotient: bit_index_quotient.try_into().unwrap(),
                    the_byte: the_byte.into(),
                    the_bit: the_bit.into(),
                    i,
                    pivot_hash: pivot_hash.into(),
                    pivot_quotient,
                };
                shuffle_row.push(row)
            }
        }

        layouter.assign_region(
            || "Shuffle Rows",
            |mut region| {
                for ShuffleRow {
                    offset,
                    list_size,
                    pivot_hash,
                    pivot,
                    mirror1,
                    mirror2,
                    flip,
                    bit_index,
                    bit_index_quotient,
                    the_byte,
                    the_bit,
                    i,
                    pivot_quotient,
                } in shuffle_row.iter()
                {
                    let seed_cells = self
                        .seed
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            region.assign_advice(
                                || format!("seed{}", i),
                                *e,
                                *offset,
                                || Value::known(F::from(seed[i] as u64)),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                    self.q_enable.enable(&mut region, *offset)?;

                    if i <= pivot {
                        self.left_half.enable(&mut region, *offset)?;
                    }
                    let pivot_hash_cells = self
                        .pivot_hash
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            region.assign_advice(
                                || format!("pivot_hash{}", i),
                                *e,
                                *offset,
                                || Value::known(F::from(pivot_hash[i] as u64)),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                    for (name, column, value) in &[
                        ("list_length", self.list_length, *list_size as u64),
                        ("pivot", self.pivot, *pivot),
                        ("mirror1", self.mirror1, *mirror1),
                        ("mirror2", self.mirror2, *mirror2),
                        ("flip", self.flip, *flip),
                        ("bit_index", self.bit_index, *bit_index),
                        (
                            "bit_index_quotient",
                            self.bit_index_quotient,
                            *bit_index_quotient,
                        ),
                        ("the_byte", self.the_byte, *the_byte),
                        ("the_bit", self.the_bit, *the_bit),
                        ("i", self.i, *i),
                        ("pivot_quotient", self.pivot_quotient, *pivot_quotient),
                    ] {
                        region.assign_advice(
                            || name.to_string(),
                            *column,
                            *offset,
                            || Value::known(F::from(*value)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

struct ShuffleRow {
    pub offset: usize,
    pub pivot_hash: [u8; 32],
    pub list_size: u64,
    pub pivot: u64,
    pub mirror1: u64,
    pub mirror2: u64,
    pub flip: u64,
    pub bit_index: u64,
    pub bit_index_quotient: u64,
    pub the_byte: u64,
    pub the_bit: u64,
    pub i: u64,
    pub pivot_quotient: u64,
}
#[cfg(test)]
mod test {
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    use super::*;

    #[derive(Default)]
    struct TestCircuit<F: Field> {
        _f: PhantomData<F>,
    }
    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = ShufflingConfig<F, 90>;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            println!("Configuring");
            ShufflingConfig::<F, 90>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let mut seed = [0u8; 32];
            seed[0] = 1;
            seed[1] = 128;
            seed[2] = 12;
            let mut input = [0u8; 10]
                .iter()
                .enumerate()
                .map(|(i, _)| i as u8)
                .collect::<Vec<_>>();

            let expected = [0u8, 7, 8, 6, 3, 9, 4, 5, 2, 1];

            config.shuffle_list(&mut layouter, &mut input, seed)?;
            assert_eq!(input, expected);

            Ok(())
        }
    }

    #[test]
    fn test_shuffling_circuit() {
        let k = 17;
        let circuit = TestCircuit::<Fr>::default();
        println!("Running prover");
        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        println!("Asserting satisfied");
        prover.assert_satisfied();
    }
}
struct ShufflingChip<F: Field> {
    config: ShufflingConfig<F, 90>,
}

impl<F: Field> Chip<F> for ShufflingChip<F> {
    type Config = ShufflingConfig<F, 90>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        todo!()
    }
}

impl<F: Field> ShufflingChip<F> {
    pub fn construct(config: ShufflingConfig<F, 90>) -> Self {
        Self { config }
    }
}
