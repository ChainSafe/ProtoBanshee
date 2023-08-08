use std::{iter, marker::PhantomData, mem, ops::Mul};

use eth_types::{Field, Mainnet, Spec};
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    is_zero,
    util::{or, select, Expr},
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
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
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

#[derive(Debug)]

pub struct ShuffleChip<'a, S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: &'a HC,
    _f: PhantomData<F>,
    _s: PhantomData<S>,
}

#[derive(Clone, Debug)]
pub struct ShufflingConfig<F: Field, const ROUNDS: usize> {
    pub seed: Column<Advice>,

    pub list_length: Column<Advice>,
    pub i: Column<Advice>, // plus one sequential
    pub list_items: Column<Advice>,

    pub q_round_ops: Selector, // 90 Rows
    pub round: Column<Advice>, // 90 * (N/2) Rows
    pub hash: Column<Advice>, // 90 Rows. (hash = sha(seed, round))[0..8] is used to calculate pivot

    pub pivot: Column<Advice>,                    // 90 Rows
    pub pivot_bytes: [Column<Advice>; U64_BYTES], // 90 * (N/2) Rows
    pub mirror1: Column<Advice>,                  // 90 Rows
    pub mirror2: Column<Advice>,                  // 90 Rows

    pub hash_bytes: Column<Advice>, // 90 * (N/2) Rows

    pub flip: Column<Advice>,               // 90 * (N/2) Rows
    pub bit_index: Column<Advice>,          // 90 * (N/2) Rows. In range [0, 255(0xff)]
    pub bit_index_quotient: Column<Advice>, // 90 * (N/2) Rows

    pub the_byte: Column<Advice>, // 90 * (N/2)
    pub the_bit: Column<Advice>,  // 90 * (N/2)

    pub left_half: [Selector; ROUNDS], // (N/2) Rows

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
    pub fn configure(meta: &mut ConstraintSystem<F>, sha256_table: Sha256Table) -> Self {
        let seed = meta.advice_column();
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
        let hash_bytes = meta.advice_column();
        let seed_concat_round_concat_i = meta.advice_column();

        let left_half: [Selector; ROUNDS] = [(); ROUNDS].map(|_| meta.complex_selector());

        let pivot_bytes: [Column<Advice>; U64_BYTES] =
            [(); U64_BYTES].map(|_| meta.advice_column());

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
            q_round_ops,
            is_zero_bit_index: None,
            is_zero_i_minus_mirror1: None,
            is_zero_i_minus_pivot_minus_1: None,
            is_zero_bit_index_minus_255: None,
            pivot_bytes,
        };

        meta.create_gate("per round variables", |m| {
            let mut cb = BaseConstraintBuilder::default();
            let pivot = m.query_advice(pivot, Rotation::cur());
            let m1 = m.query_advice(mirror1, Rotation::cur());
            let m2 = m.query_advice(mirror2, Rotation::cur());
            let list_length = m.query_advice(list_length, Rotation::cur());
            let q_round_ops = m.query_selector(q_round_ops);
            let pivot_bytes = pivot_bytes.map(|c| m.query_advice(c, Rotation::cur()));

            // TODO: Restrict Pivot_bytes to be hash[0 ..8]
            cb.require_equal(
                "pivot_bytes == pivot",
                pivot.clone(),
                from_u64_bytes::expr(&pivot_bytes),
            );
            cb.require_equal(
                "mirror m1 = (pivot + 2) / 2",
                2u64.expr() * m1,
                pivot.clone() + 2u64.expr(),
            );
            cb.require_equal(
                "mirror m2 = (pivot + list_length) / 2",
                2u64.expr() * m2,
                pivot + list_length,
            );
            cb.gate(q_round_ops)
        });

        // // TODO: Enforce concat(seed, round) == seed_concat_round
        // meta.lookup_any("hash = sha256(seed, round) as byte", |meta| {
        //     let seed_concat_round = meta.query_advice(seed_concat_round, Rotation::cur());
        //     let q_round_ops = meta.query_selector(q_round_ops);

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

            let is_zero_bit_index = IsZeroGadget::construct(&mut cb, bit_index.clone());
            let is_zero_bit_index_minus_255 =
                IsZeroGadget::construct(&mut cb, bit_index.clone() - 255.expr());
            let is_zero_i_minus_mirror1 =
                IsZeroGadget::construct(&mut cb, i.clone() - mirror1.clone());
            let is_zero_i_minus_pivot_minus_1 =
                IsZeroGadget::construct(&mut cb, i.clone() - pivot.clone() - 1.expr());

            for r in 0..ROUNDS {
                let is_left = meta.query_selector(left_half[r]);
                let f = select::expr(
                    is_left.clone(),
                    pivot.clone() - i.clone(),
                    pivot.clone() + list_length.clone() - i.clone(),
                );
                cb.require_equal("flip = pivot - i or pivot + list size - i", flip.clone(), f);

                let i_or_flip = select::expr(is_left.clone(), i.clone(), flip.clone());
                cb.require_equal(
                    "bit_index = i & 0xff or flip & 0xff",
                    bit_index_quotient.clone() * 256.expr(),
                    i_or_flip - bit_index.clone(),
                );
            }

            config.is_zero_bit_index = Some(is_zero_bit_index);
            config.is_zero_i_minus_mirror1 = Some(is_zero_i_minus_mirror1);
            config.is_zero_i_minus_pivot_minus_1 = Some(is_zero_i_minus_pivot_minus_1);
            config.is_zero_bit_index_minus_255 = Some(is_zero_bit_index_minus_255);

            cb.gate(1.expr())
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
        config
    }

    pub fn shuffle(&self, layouter: &mut impl Layouter<F>, input: &mut Vec<u8>, seed: [u8; 32]) {
        let list_size = input.len() as u64;
        for round in 89u8..0 {
            let round_as_byte = round.to_be_bytes();
            let hash = sha2::Sha256::digest(vec![seed.to_vec(), round_as_byte.to_vec()].concat());
            let pivot = hash[0..8].to_vec();
            let pivot = u64::from_le_bytes(pivot.try_into().unwrap());
            let pivot = pivot % list_size;

            let mut hash_bytes = [0u8; 32];
            let mirror1 = (pivot + 2) / 2;
            let mirror2 = (pivot + list_size) / 2;
            for i in mirror1..=mirror2 {
                let (flip, bit_index) = if i <= pivot {
                    let flip = pivot - i;
                    let bit_index = i & 0xff;
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
                    (flip, bit_index)
                } else {
                    let flip = pivot + list_size - i;
                    let bit_index = flip & 0xff;
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

                    (flip, bit_index)
                };

                let the_byte = hash[(bit_index / 8) as usize];
                let the_bit = (the_byte >> (bit_index & 0x07)) & 1;
                if the_bit != 0 {
                    let tmp = input[i as usize];
                    input[i as usize] = input[flip as usize];
                    input[flip as usize] = tmp;
                }
                layouter.assign_region(
                    || "dunno",
                    |mut region| {
                        if i <= pivot {
                            self.left_half[round as usize].enable(&mut region, i as usize)?;
                        }
                        self.pivot_bytes.iter().enumerate().map(|(i, e)| {
                            region.assign_advice(
                                || format!("pivot_bytes{}", i),
                                *e,
                                0,
                                || Value::known(F::from(pivot.to_le_bytes()[i] as u64)),
                            )
                        });
                        for (name, column, value) in &[
                            ("pivot", self.pivot, pivot),
                            ("mirror1", self.mirror1, mirror1),
                            ("mirror2", self.mirror2, mirror2),
                            ("flip", self.flip, flip),
                            ("bit_index", self.bit_index, bit_index),
                            ("the_byte", self.the_byte, the_byte.into()),
                            ("the_bit", self.the_bit, the_bit.into()),
                        ] {
                            region.assign_advice(
                                || name.to_string(),
                                *column,
                                i as usize,
                                || Value::known(F::from(*value)),
                            )?;
                        }
                        Ok(())
                    },
                );
            }
        }
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

// Teku shuffling algorithm
// public void shuffleList(int[] input, Bytes32 seed) {

//     int listSize = input.length;
//     if (listSize == 0) {
//       return;
//     }

//     final Sha256 sha256 = getSha256Instance();

//     for (int round = specConfig.getShuffleRoundCount() - 1; round >= 0; round--) {

//       final Bytes roundAsByte = Bytes.of((byte) round);

//       // This needs to be unsigned modulo.
//       final Bytes hash = sha256.wrappedDigest(seed, roundAsByte);
//       int pivot = bytesToUInt64(hash.slice(0, 8)).mod(listSize).intValue();

//       byte[] hashBytes = EMPTY_HASH;
//       int mirror1 = (pivot + 2) / 2; --------OK
//       int mirror2 = (pivot + listSize) / 2; ---------OK
//       for (int i = mirror1; i <= mirror2; i++) {
//         int flip, bitIndex; ------------OK
//         if (i <= pivot) {
//           flip = pivot - i;
//           bitIndex = i & 0xff;
//           if (bitIndex == 0 || i == mirror1) {
//             hashBytes = sha256.digest(seed, roundAsByte, uintTo4Bytes(i / 256));
//           }
//         } else {
//           flip = pivot + listSize - i;
//           bitIndex = flip & 0xff;
//           if (bitIndex == 0xff || i == pivot + 1) {
//             hashBytes = sha256.digest(seed, roundAsByte, uintTo4Bytes(flip / 256));
//           }
//         }

//         int theByte = hashBytes[bitIndex / 8];
//         int theBit = (theByte >> (bitIndex & 0x07)) & 1;
//         if (theBit != 0) {
//           int tmp = input[i];
//           input[i] = input[flip];
//           input[flip] = tmp;
//         }
//       }
//     }
//   }
