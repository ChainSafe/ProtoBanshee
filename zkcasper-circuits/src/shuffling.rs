use std::{iter, marker::PhantomData, mem, ops::Mul};

use eth_types::{Field, Mainnet, Spec};
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::{select, Expr},
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
    gadget::crypto::{AssignedHashResult, HashChip},
    sha256_circuit::Sha256CircuitConfig,
    table::Sha256Table,
    // table::SHA256Table,
    util::{BaseConstraintBuilder, SubCircuitConfig},
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

    pub flip: Column<Advice>,      // 90 * (N/2) Rows
    pub bit_index: Column<Advice>, // 90 * (N/2) Rows

    pub the_byte: Column<Advice>, // 90 * (N/2)
    pub the_bit: Column<Advice>,  // 90 * (N/2)

    pub left_half: [Selector; ROUNDS], // (N/2) Rows

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
        let left_half: [Selector; ROUNDS] = [(); ROUNDS].map(|_| meta.complex_selector());

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
            for r in 0..ROUNDS {
                let flip = meta.query_advice(flip, Rotation::cur());
                let i = meta.query_advice(i, Rotation::cur());
                let pivot = meta.query_advice(pivot, Rotation::cur());
                let list_length = meta.query_advice(list_length, Rotation::cur());
                let bit_index = meta.query_advice(bit_index, Rotation::cur());
                let is_left = meta.query_selector(left_half[r]);

                let f = select::expr(
                    is_left.clone(),
                    pivot.clone() - i.clone(),
                    pivot + list_length - i.clone(),
                );
                cb.require_equal("flip = pivot - i or pivot + list size - i", flip.clone(), f);

                let i_or_flip = select::expr(is_left, i, flip.clone());
                // FIXME: How to constrain congruency mod 256? or & 0xff which is the same thing...
                cb.require_equal(
                    "bit_index = i & 0xff or flip & 0xff",
                    bit_index * 256.expr(),
                    i_or_flip,
                );
            }

            cb.gate(1.expr())
        });

        Self {
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
            left_half,
            sha256,
        }
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
