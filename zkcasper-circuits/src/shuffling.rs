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
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
    poly::Rotation,
};
use num_bigint::BigUint;

use crate::{
    gadget::{
        crypto::{AssignedHashResult, HashChip},
        math::IsZeroGadget,
    },
    sha256_circuit::Sha256CircuitConfig,
    table::Sha256Table,
    // table::SHA256Table,
    util::{BaseConstraintBuilder, ConstrainBuilderCommon, SubCircuitConfig},
    witness::{HashInput, HashInputChunk},
};

const SEED_SIZE: usize = 32;
const ROUND_SIZE: usize = 1;
const POSITION_WINDOW_SIZE: usize = 4;
const PIVOT_VIEW_SIZE: usize = SEED_SIZE + ROUND_SIZE;
const TOTAL_SIZE: usize = SEED_SIZE + ROUND_SIZE + POSITION_WINDOW_SIZE;

#[derive(Debug)]

pub struct ShuffleChip<'a, S: Spec, F: Field, HC: HashChip<F>> {
    hash_chip: &'a HC,
    _f: PhantomData<F>,
    _s: PhantomData<S>,
}

#[derive(Clone, Debug)]
pub struct ShufflingConfig<F: Field, const ROUNDS: usize> {
    pub list_length: Column<Advice>,
    pub i: Column<Advice>, // plus one sequential
    pub list_items: Column<Advice>,

    pub round: Column<Advice>,   // 90 * (N/2) Rows
    pub pivot: Column<Advice>,   // 90 Rows
    pub mirror1: Column<Advice>, // 90 Rows
    pub mirror2: Column<Advice>, // 90 Rows

    pub flip: Column<Advice>,               // 90 * (N/2) Rows
    pub bit_index: Column<Advice>,          // 90 * (N/2) Rows. In range [0, 255(0xff)]
    pub bit_index_quotient: Column<Advice>, // 90 * (N/2) Rows

    pub the_byte: Column<Advice>, // 90 * (N/2)
    pub the_bit: Column<Advice>,  // 90 * (N/2)

    pub left_half: [Selector; ROUNDS], // (N/2) Rows

    pub is_zero_bit_index: Option<IsZeroGadget<F>>,
    pub is_zero_i_minus_mirror1: Option<IsZeroGadget<F>>,
    pub is_zero_i_minus_pivot_minus_1: Option<IsZeroGadget<F>>,
    pub is_zero_bit_index_minus_255: Option<IsZeroGadget<F>>,

    pub sha256: Sha256CircuitConfig<F>,
}

impl<const ROUNDS: usize, F: Field> ShufflingConfig<F, ROUNDS> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let sha256_table = Sha256Table::construct(meta);
        let sha256 = Sha256CircuitConfig::new::<Mainnet>(meta, sha256_table);

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
        let left_half: [Selector; ROUNDS] = [(); ROUNDS].map(|_| meta.complex_selector());

        let mut config = Self {
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
            sha256,
            is_zero_bit_index: None,
            is_zero_i_minus_mirror1: None,
            is_zero_i_minus_pivot_minus_1: None,
            is_zero_bit_index_minus_255: None,
        };

        meta.create_gate("per round variables", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let pivot = meta.query_advice(pivot, Rotation::cur());
            let m1 = meta.query_advice(mirror1, Rotation::cur());
            let m2 = meta.query_advice(mirror2, Rotation::cur());
            let list_length = meta.query_advice(list_length, Rotation::cur());

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
            cb.gate(1.expr())
        });

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

                // if is_left AND bit_index == 0 OR i == mirror1 -> Hash
                // else if NOT is_left AND bit_index == 255 OR i == pivot + 1 -> Hash
                // else -> No Hash

                select::expr(
                    is_left.clone(),
                    select::expr(
                        or::expr(
                            [is_zero_bit_index.expr(), is_zero_i_minus_mirror1.expr()].into_iter(),
                        ),
                        1.expr(), // Do lookup table on new hash value
                        0.expr(), // Hash stays the same
                    ),
                    select::expr(
                        or::expr(
                            [
                                is_zero_bit_index_minus_255.expr(),
                                is_zero_i_minus_pivot_minus_1.expr(),
                            ]
                            .into_iter(),
                        ),
                        2.expr(), // Do lookup table on new hash value
                        0.expr(), // Hash stays the same
                    ),
                );
            }

            config.is_zero_bit_index = Some(is_zero_bit_index);
            config.is_zero_i_minus_mirror1 = Some(is_zero_i_minus_mirror1);
            config.is_zero_i_minus_pivot_minus_1 = Some(is_zero_i_minus_pivot_minus_1);
            config.is_zero_bit_index_minus_255 = Some(is_zero_bit_index_minus_255);

            cb.gate(1.expr())
        });

        config
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
//       int mirror1 = (pivot + 2) / 2;
//       int mirror2 = (pivot + listSize) / 2;
//       for (int i = mirror1; i <= mirror2; i++) {
//         int flip, bitIndex;
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
