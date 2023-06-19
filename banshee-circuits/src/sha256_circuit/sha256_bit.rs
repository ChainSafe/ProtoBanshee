use super::util::*;
use crate::{
    util::{not, rlc, BaseConstraintBuilder, Expr},
    witness::HashInput,
};
use eth_types::Field;
use gadgets::util::{and, select, sum, xor};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use log::{debug, info};
use snark_verifier::loader::LoadedScalar;
use std::{env::var, io::Read, marker::PhantomData, vec};

#[derive(Clone, Debug, PartialEq)]
pub struct ShaRow<F> {
    pub(crate) w: [bool; NUM_BITS_PER_WORD_W],
    pub(crate) a: [bool; NUM_BITS_PER_WORD_EXT],
    pub(crate) e: [bool; NUM_BITS_PER_WORD_EXT],
    pub(crate) is_final: bool,
    pub(crate) length: usize,
    pub(crate) data_rlc: F,
    pub(crate) hash_rlc: F,
    pub(crate) is_paddings: [bool; ABSORB_WIDTH_PER_ROW_BYTES],
    pub(crate) intermediary_data_rlcs: [F; ABSORB_WIDTH_PER_ROW_BYTES],
    pub(crate) final_hash_bytes: [F; NUM_BYTES_FINAL_HASH],

    pub(crate) limb_rlc: F,
    pub(crate) limbs_rlc: [F; 2],
    pub(crate) intermediary_limb_rlcs: [F; ABSORB_WIDTH_PER_ROW_BYTES],
}

pub fn sha256<F: Field>(rows: &mut Vec<ShaRow<F>>, inputs: &[&[u8]; 2], rnd: F) {
    let left_bits = into_bits(inputs[0]);
    let right_bits = into_bits(inputs[1]);
    let input_len = inputs[0].len() + inputs[1].len();

    let mut bits = left_bits
        .iter()
        .copied()
        .chain(right_bits.clone())
        .collect_vec();

    // Prepare inputs RLCs in advance
    let mut inputs_rlc = [F::zero(), F::zero()];
    for (idx, bytes) in inputs.iter().enumerate() {
        for byte in inputs[idx].iter() {
            inputs_rlc[idx] = inputs_rlc[idx] * rnd + F::from(*byte as u64);
        }

        println!("inputs_rlc[{}] = {:?}", idx, inputs_rlc[idx])
    }

    // let mut bytes_rlc = F::zero();
    // for byte in inputs[0].iter().copied().chain(inputs[1].iter().copied()).collect_vec()
    // {
    //     bytes_rlc = bytes_rlc * rnd + F::from(byte as u64);
    // }

    // let mut r_pow_m = rnd.clone();

    // r_pow_m = rnd.pow_const(inputs[1].len() as u64);

    // assert_eq!(bytes_rlc, inputs_rlc[0] * r_pow_m + inputs_rlc[1]);

    // Padding
    let length = bits.len();
    let mut length_in_bits = into_bits(&(length as u64).to_be_bytes());
    assert!(length_in_bits.len() == NUM_BITS_PADDING_LENGTH);
    bits.push(1);
    while (bits.len() + NUM_BITS_PADDING_LENGTH) % RATE_IN_BITS != 0 {
        bits.push(0);
    }
    bits.append(&mut length_in_bits);
    assert!(bits.len() % RATE_IN_BITS == 0);

    // Set the initial state
    let mut hs: [u64; 8] = H
        .iter()
        .map(|v| *v as u64)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut length = 0usize;
    let mut data_rlc = F::zero();
    let mut limb_rlc = F::zero();

    let mut in_padding = false;

    // Process each block
    let chunks = bits.chunks(RATE_IN_BITS);
    let num_chunks = chunks.len();
    for (idx, chunk) in chunks.enumerate() {
        // Adds a row
        let mut add_row = |w: u64,
                           a: u64,
                           e: u64,
                           is_final,
                           length,
                           data_rlc,
                           hash_rlc,
                           is_paddings,
                           intermediary_data_rlcs,
                           final_hash_bytes,
                           limb_rlc,
                           intermediary_limb_rlcs|{
            let word_to_bits = |value: u64, num_bits: usize| {
                into_bits(&value.to_be_bytes())[64 - num_bits..64]
                    .iter()
                    .map(|b| *b != 0)
                    .into_iter()
                    .collect::<Vec<_>>()
            };
            // println!("    row[data_rlc]: {:?}", data_rlc);
            // data_rlcs.iter().for_each(|e| println!("row[data_rlcs]: {:?}", e));
            rows.push(ShaRow {
                w: word_to_bits(w, NUM_BITS_PER_WORD_W).try_into().unwrap(),
                a: word_to_bits(a, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                e: word_to_bits(e, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                is_final,
                length,
                data_rlc,
                hash_rlc,
                is_paddings,
                intermediary_data_rlcs,
                final_hash_bytes,
                limbs_rlc: if is_final {
                    inputs_rlc
                } else {
                    [data_rlc, F::zero()]
                },
                limb_rlc,
                intermediary_limb_rlcs,
            });
            //println!("    row: {:?}", (is_final, length, data_rlc, is_paddings));
        };

        // Last block for this hash
        let is_final_block = idx == num_chunks - 1;

        // Set the state
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7]);

        // Add start rows
        let mut add_row_start = |a: u64, e: u64, is_final| {
            add_row(
                0,
                a,
                e,
                is_final,
                length,
                data_rlc,
                F::zero(),
                [false, false, false, in_padding],
                [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
                [F::zero(); NUM_BYTES_FINAL_HASH],
                limb_rlc,
                [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
            )
        };
        add_row_start(d, h, idx == 0);
        add_row_start(c, g, idx == 0);
        add_row_start(b, f, idx == 0);
        add_row_start(a, e, idx == 0);

        let mut ws = Vec::new();
        for (round, round_cst) in ROUND_CST.iter().enumerate() {
            // Padding/Length/Data rlc
            let mut is_paddings = [false; ABSORB_WIDTH_PER_ROW_BYTES];
            let mut inter_data_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
            let mut inter_limb_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
            if length % 32 == 0 {
                // println!("---> round {round} length {length}");
                limb_rlc = F::zero();
            }
            if round < NUM_WORDS_TO_ABSORB {
                // padding/length
                for is_padding in is_paddings.iter_mut() {
                    *is_padding = if length == input_len {
                        true
                    } else {
                        length += 1;
                        false
                    };
                }
                // data rlc
                let input_bytes = to_le_bytes::value(&chunk[round * 32..(round + 1) * 32]);
                inter_data_rlcs[0] = data_rlc;
                inter_limb_rlcs[0] = limb_rlc;
                // println!("round {round} new_input_rlc: {:?}", limb_rlc);
                // println!("round {round} input_bytes = {:?}", input_bytes);

                for (idx, (byte, padding)) in input_bytes.iter().zip(is_paddings.iter()).enumerate()
                {
                    if !*padding {
                        data_rlc = data_rlc * rnd + F::from(*byte as u64);
                        limb_rlc = limb_rlc * rnd + F::from(*byte as u64);
                    }
                    if idx < inter_data_rlcs.len() - 1 {
                        inter_data_rlcs[idx + 1] = data_rlc;
                        inter_limb_rlcs[idx + 1] = limb_rlc;
                    }
                }
                // println!("new_input_rlc: {:?}", limb_rlc);

                in_padding = *is_paddings.last().unwrap();
            }

            // w
            let w_ext = if round < NUM_WORDS_TO_ABSORB {
                decode::value(&chunk[round * 32..(round + 1) * 32])
            } else {
                let get_w = |offset: usize| ws[ws.len() - offset] & 0xFFFFFFFF;
                let s0 = rotate::value(get_w(15), 7)
                    ^ rotate::value(get_w(15), 18)
                    ^ shift::value(get_w(15), 3);
                let s1 = rotate::value(get_w(2), 17)
                    ^ rotate::value(get_w(2), 19)
                    ^ shift::value(get_w(2), 10);
                get_w(16) + s0 + get_w(7) + s1
            };
            let w = w_ext & 0xFFFFFFFF;
            ws.push(w);

            // compression
            let s1 = rotate::value(e, 6) ^ rotate::value(e, 11) ^ rotate::value(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h + s1 + ch + (*round_cst as u64) + w;
            let s0 = rotate::value(a, 2) ^ rotate::value(a, 13) ^ rotate::value(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;

            // Add the row
            add_row(
                w_ext,
                a,
                e,
                false,
                if round < NUM_WORDS_TO_ABSORB {
                    length
                } else {
                    0
                },
                if round < NUM_WORDS_TO_ABSORB {
                    data_rlc
                } else {
                    F::zero()
                },
                F::zero(),
                is_paddings,
                inter_data_rlcs,
                [F::zero(); NUM_BYTES_FINAL_HASH],
                if round < NUM_WORDS_TO_ABSORB {
                    limb_rlc
                } else {
                    F::zero()
                },
                inter_limb_rlcs
            );

            // Truncate the newly calculated values
            a &= 0xFFFFFFFF;
            e &= 0xFFFFFFFF;
        }

        // Accumulate
        hs[0] += a;
        hs[1] += b;
        hs[2] += c;
        hs[3] += d;
        hs[4] += e;
        hs[5] += f;
        hs[6] += g;
        hs[7] += h;

        // Squeeze

        let hash_rlc = if is_final_block {
            let hash_bytes = hs
                .iter()
                .flat_map(|h| (*h as u32).to_be_bytes())
                .collect::<Vec<_>>();
            rlc::value(&hash_bytes, rnd)
        } else {
            F::zero()
        };

        let final_hash_bytes = if is_final_block {
            let mut bytes = [F::zero(); NUM_BYTES_FINAL_HASH];
            for (i, h) in hs.iter().enumerate() {
                for (j, byte) in (*h as u32).to_be_bytes().into_iter().enumerate() {
                    bytes[4 * i + j] = F::from(byte as u64);
                }
            }
            bytes
        } else {
            [F::zero(); NUM_BYTES_FINAL_HASH]
        };

        // Add end rows
        let mut add_row_end = |a: u64, e: u64| {
            add_row(
                0,
                a,
                e,
                false,
                0,
                F::zero(),
                F::zero(),
                [false; ABSORB_WIDTH_PER_ROW_BYTES],
                [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
                [F::zero(); NUM_BYTES_FINAL_HASH],
                F::zero(),
                [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
            )
        };
        add_row_end(hs[3], hs[7]);
        add_row_end(hs[2], hs[6]);
        add_row_end(hs[1], hs[5]);

        add_row(
            0,
            hs[0],
            hs[4],
            is_final_block,
            length,
            data_rlc,
            hash_rlc,
            [false, false, false, in_padding],
            [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
            final_hash_bytes,
            limb_rlc,
            [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
        );

        // Now truncate the results
        for h in hs.iter_mut() {
            *h &= 0xFFFFFFFF;
        }
    }

    let hash_bytes = hs
        .iter()
        .flat_map(|h| (*h as u32).to_be_bytes())
        .collect::<Vec<_>>();

    debug!("hash: {:x?}", &hash_bytes);
    debug!("data rlc: {:x?}", data_rlc);
}

pub fn multi_sha256<F: Field>(inputs: &[HashInput], rnd: F) -> Vec<ShaRow<F>> {
    let inputs = inputs
        .iter()
        .map(|input| match input {
            HashInput::Single(bytes) => [bytes.as_slice(), &[]],
            HashInput::MerklePair(left, right) => [left.as_slice(), right.as_slice()],
        })
        .collect_vec();
    let mut rows: Vec<ShaRow<F>> = Vec::new();
    for bytes in inputs {
        sha256(&mut rows, &bytes, rnd);
    }
    rows
}
