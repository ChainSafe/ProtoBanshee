use std::{iter, marker::PhantomData, mem, ops::Mul};

use eth_types::{Field, Mainnet, Spec};
use ethereum_consensus::crypto::hash;
use gadgets::{
    binary_number::{AsBits, BinaryNumberChip, BinaryNumberConfig},
    is_zero,
    util::{not, or, rlc, select, Expr},
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
use itertools::Itertools;
use num_bigint::BigUint;
use sha2::Digest;

use crate::{
    gadget::{
        crypto::{AssignedHashResult, HashChip},
        math::IsZeroGadget,
    },
    sha256_circuit::Sha256CircuitConfig,
    table::{sha256_table, Sha256Table},
    util::{
        from_bytes, from_u64_bytes, to_bytes, BaseConstraintBuilder, ConstrainBuilderCommon,
        SubCircuitConfig,
    },
    witness::{self, HashInput, HashInputChunk},
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
    pub the_byte_as_bits: [Column<Advice>; 8],
    pub the_bit: Column<Advice>, // 90 * (N/2) u8
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
    pub fn configure(meta: &mut ConstraintSystem<F>, sha256_table: Sha256Table, rand: F) -> Self {
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
        meta.enable_equality(the_byte);
        let the_bit = meta.advice_column();
        meta.enable_equality(the_bit);
        let the_byte_as_bits = [(); 8].map(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);
            col
        });
        let bit_index_quotient = meta.advice_column();
        let seed_concat_round = meta.advice_column();
        let hash_bytes = [(); 32].map(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);
            col
        });
        let seed_concat_round_concat_i = meta.advice_column();

        let left_half = meta.complex_selector();
        let q_enable = meta.complex_selector();

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
            the_byte_as_bits,
            the_byte,
            the_bit,
            bit_index_quotient,
            left_half,
            sha256_table,
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

        meta.lookup_any("hash = sha256(seed, round) as byte", |meta| {
            let seed = seed.map(|s| meta.query_advice(s, Rotation::cur()));
            let round = meta.query_advice(round, Rotation::cur());
            let seed_plus_round = rlc::expr(
                &seed
                    .iter()
                    .chain(std::iter::once(&round))
                    .map(|s| s.clone())
                    .collect::<Vec<_>>(),
                Expression::Constant(rand),
            );
            let q_enable = meta.query_selector(q_enable);
            let pivot_hash = pivot_hash.map(|c| meta.query_advice(c, Rotation::cur()));

            config.sha256_table.build_lookup(
                meta,
                q_enable,
                seed_plus_round,
                0.expr(),
                rlc::expr(&pivot_hash, Expression::Constant(rand)),
            )
        });

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
            let the_byte = meta.query_advice(the_byte, Rotation::cur());
            let q_enable = meta.query_selector(q_enable);
            let left_half = meta.query_selector(left_half);
            let the_byte_as_bits = the_byte_as_bits.map(|c| meta.query_advice(c, Rotation::cur()));

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
            cb.require_equal(
                "the_byte = the_byte_as_bit",
                the_byte,
                to_bytes::expr(&the_byte_as_bits)[0].clone(),
            );

            cb.gate(q_enable)
        });

        println!("shuffling circuit degree={}", meta.degree());

        config
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &[ShuffleRow],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Shuffle Rows",
            |mut region| {
                for ShuffleRow {
                    seed,
                    round,
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
                    hash_bytes,
                } in witness.iter()
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

                    let hash_bytes_cells = self
                        .hash_bytes
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            region.assign_advice(
                                || format!("hash_bytes{}", i),
                                *e,
                                *offset,
                                || Value::known(F::from(hash_bytes[i] as u64)),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                    let the_byte_cell = hash_bytes_cells[(bit_index / 8) as usize].copy_advice(
                        || "the_byte",
                        &mut region,
                        self.the_byte,
                        *offset,
                    )?;

                    let mut the_byte_as_bits: [bool; 8] = (*the_byte as u8).as_bits();
                    the_byte_as_bits.reverse();
                    let the_byte_as_bits_cells = self
                        .the_byte_as_bits
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            region.assign_advice(
                                || format!("the_byte_as_bit{}", i),
                                *e,
                                *offset,
                                || Value::known(F::from(the_byte_as_bits[i] as u64)),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    let the_bit_cell = the_byte_as_bits_cells
                        [(the_byte >> (*bit_index % 8)) as usize & 1]
                        .copy_advice(|| "the_bit", &mut region, self.the_bit, *offset)?;

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
                        ("i", self.i, *i),
                        ("pivot_quotient", self.pivot_quotient, *pivot_quotient),
                        ("round", self.round, *round as u64),
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

    // Generates witness data
    pub fn shuffle_list(input: &mut [u8], seed: [u8; 32]) -> Result<Vec<ShuffleRow>, Error> {
        let list_size = input.len();
        if list_size == 0 {
            return Ok(vec![]);
        }

        let mut shuffle_row = vec![];
        let mut offset = 0u64;

        for round in (0..90).rev() {
            let round_as_byte: [u8; 1] = [round as u8];

            let pivot_hash =
                sha2::Sha256::digest(vec![seed.to_vec(), round_as_byte.to_vec()].concat());

            let pivot = u64::from_le_bytes(pivot_hash[0..8].try_into().expect("Expected 8 bytes"));

            let pivot_quotient = pivot / list_size as u64;
            println!(
                "pivot is: {:#X?}, pivot_quotient is {:#X?} pivot is {:#X?}, and pivot hash le: {:#X?}",
                pivot,
                pivot_quotient,
                pivot % list_size as u64,
                &pivot_hash[0..8]
            );
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

                let byte_index = bit_index / 8;
                let byte_index_rem = bit_index % 8;

                let the_byte = hash_bytes[byte_index];
                let the_bit = (the_byte >> byte_index_rem) & 1;
                if the_bit != 0 {
                    input.swap(i as usize, flip as usize);
                }

                println!(
                    "is_left: {} Offset {} Round {} pivot {} mirror1 {} mirror2 {} flip {} bit_index {} bit_index_quotient {} the_byte {} the_bit {} i {}",
                    i<= pivot, offset, round, pivot, mirror1, mirror2, flip, bit_index, bit_index_quotient, the_byte, the_bit, i);
                offset += 1;
                let row = ShuffleRow {
                    hash_bytes,
                    seed,
                    round,
                    offset: offset.try_into().unwrap(),
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

        Ok(shuffle_row)
    }
}

pub struct ShuffleRow {
    pub seed: [u8; 32],
    pub round: u8,
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
    pub hash_bytes: [u8; 32],
}

impl ShuffleRow {
    fn sha256_inputs(rows: &[Self]) -> Vec<HashInput<u8>> {
        rows.iter()
            .map(|row| {
                let mut input = row.seed.to_vec();
                input.push(row.round);
                HashInput::Single(HashInputChunk {
                    bytes: input,
                    is_rlc: true,
                })
            })
            .collect_vec()
    }
}
#[cfg(test)]
mod test {
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    use crate::util::Challenges;

    use super::*;

    #[derive(Default)]
    struct TestCircuit<F: Field> {
        _f: PhantomData<F>,
    }
    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = (ShufflingConfig<F, 90>, Challenges<Value<F>>);

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_table = Sha256Table::construct(meta);

            let config = ShufflingConfig::<F, 90>::configure(
                meta,
                sha256_table,
                Sha256CircuitConfig::fixed_challenge(),
            );
            (
                config,
                Challenges::mock(Value::known(Sha256CircuitConfig::fixed_challenge())),
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let seed: [u8; 32] =
                hex::decode("4ac96f664a6cafd300b161720809b9e17905d4d8fed7a97ff89cf0080a953fe7")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let expected = [
                19, 6, 0, 1, 24, 16, 9, 23, 27, 20, 18, 8, 22, 21, 4, 3, 13, 14, 5, 15, 25, 11, 12,
                30, 7, 31, 17, 10, 2, 28, 26, 29, 32,
            ];
            // let expected = [0, 6, 8, 2, 7, 9, 3, 4, 5, 1];
            let mut input = expected
                .iter()
                .enumerate()
                .map(|(i, _)| i as u8)
                .collect::<Vec<_>>();

            let witness = ShufflingConfig::<F, 90>::shuffle_list(&mut input, seed)?;
            let hash_inputs = ShuffleRow::sha256_inputs(&witness);
            config
                .0
                .sha256_table
                .dev_load(&mut layouter, &hash_inputs, config.1.sha256_input())?;
            config.0.assign(&mut layouter, &witness)?;
            assert_eq!(input, expected);

            Ok(())
        }
    }

    #[test]
    fn test_shuffling_circuit() {
        let k = 13;
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
