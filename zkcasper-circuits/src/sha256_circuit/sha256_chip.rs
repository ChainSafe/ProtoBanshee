use std::collections::HashMap;

use eth_types::Field;
use itertools::Itertools;
// //! Gadget and chips for the [SHA-256] hash function.
// //!
// //! [SHA-256]: https://tools.ietf.org/html/rfc6234
use crate::sha256_circuit::{
    sha256_compression::{Sha256AssignedRows, Sha256CompressionConfig},
    util::H,
};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus},
    AssignedValue, Context,
};
use halo2_base::{safe_types::RangeChip, utils::ScalarField};
use halo2_base::{
    utils::{fe_to_bigint, value_to_option},
    ContextCell,
};
use halo2_proofs::{
    circuit::{self, AssignedCell, Cell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
        TableColumn, VirtualCells,
    },
    poly::Rotation,
};
use sha2::{Digest, Sha256};

const Sha256BitChipRowPerRound: usize = 72;
const BLOCK_BYTE: usize = 64;
const DIGEST_BYTE: usize = 32;
const SHA256_CONTEXT_ID: usize = usize::MAX;

#[derive(Debug, Clone)]
pub struct AssignedHashResult<F: Field> {
    pub input_len: AssignedValue<F>,
    pub input_bytes: Vec<AssignedValue<F>>,
    pub output_bytes: Vec<AssignedValue<F>>,
}

pub struct Sha256Chip<'a, F: Field> {
    sha256_comp_configs: Vec<Sha256CompressionConfig<F>>,
    pub max_byte_size: usize,
    range: &'a RangeChip<F>,
}

impl<'a, F: Field> Sha256Chip<'a, F> {
    const ONE_ROUND_INPUT_BYTES: usize = 64;

    pub fn new(
        sha256_comp_configs: Vec<Sha256CompressionConfig<F>>,
        range: &'a RangeChip<F>,
        max_byte_size: usize,
    ) -> Self {
        Self {
            sha256_comp_configs,
            max_byte_size,
            range,
        }
    }

    pub fn digest(
        &self,
        input: &'a [u8],
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        assigned_advices: &mut HashMap<(usize, usize), (circuit::Cell, usize)>,
        witness_gen_only: bool,
    ) -> Result<AssignedHashResult<F>, Error> {
        let input_byte_size = input.len();
        let input_byte_size_with_9 = input_byte_size + 9;
        let one_round_size = Self::ONE_ROUND_INPUT_BYTES;
        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let max_byte_size = self.max_byte_size;
        let max_round = max_byte_size / one_round_size;
        debug_assert!(padded_size <= max_byte_size);
        let zero_padding_byte_size = padded_size - input_byte_size_with_9;
        let remaining_byte_size = max_byte_size - padded_size;
        debug_assert_eq!(
            remaining_byte_size,
            one_round_size * (max_round - num_round)
        );
        let mut padded_inputs = input.to_vec();
        padded_inputs.push(0x80);
        for _ in 0..zero_padding_byte_size {
            padded_inputs.push(0);
        }
        let mut input_len_bytes = [0; 8];
        let le_size_bytes = (8 * input_byte_size).to_le_bytes();
        input_len_bytes[0..le_size_bytes.len()].copy_from_slice(&le_size_bytes);
        for byte in input_len_bytes.iter().rev() {
            padded_inputs.push(*byte);
        }

        assert_eq!(padded_inputs.len(), num_round * one_round_size);
        for _ in 0..remaining_byte_size {
            padded_inputs.push(0);
        }
        assert_eq!(padded_inputs.len(), max_byte_size);

        let range = self.range();
        let gate = range.gate();

        let assigned_input_byte_size = ctx.load_witness(F::from(input_byte_size as u64));
        let assigned_num_round = ctx.load_witness(F::from(num_round as u64));
        let padded_size = gate.mul(
            ctx,
            QuantumCell::Existing(assigned_num_round.clone()),
            QuantumCell::Constant(F::from(one_round_size as u64)),
        );
        let assigned_input_with_9_size = gate.add(
            ctx,
            QuantumCell::Existing(assigned_input_byte_size.clone()),
            QuantumCell::Constant(F::from(9u64)),
        );
        let padding_size = gate.sub(
            ctx,
            QuantumCell::Existing(padded_size.clone()),
            QuantumCell::Existing(assigned_input_with_9_size.clone()),
        );
        let padding_is_less_than_round =
            range.is_less_than_safe(ctx, padding_size, one_round_size as u64);
        gate.assert_is_const(ctx, &padding_is_less_than_round, &F::one());

        let num_column = self.sha256_comp_configs.len();
        let num_round_per_column = max_round / num_column;

        let mut last_hs = H;
        let mut assigned_last_hs_vec = vec![H
            .iter()
            .map(|h| ctx.load_constant(F::from(*h)))
            .collect::<Vec<AssignedValue<F>>>()];
        let assigned_input_bytes = padded_inputs
            .iter()
            .map(|byte| ctx.load_witness(F::from(*byte as u64)))
            .collect::<Vec<AssignedValue<F>>>();
        for &assigned_byte in assigned_input_bytes.iter() {
            range.range_check(ctx, assigned_byte, 8);
        }

        for n_column in 0..num_column {
            let sha2_comp_config = &self.sha256_comp_configs[n_column];
            for n_round in 0..num_round_per_column {
                let round_idx = n_column * num_round_per_column + n_round;
                let (witness, next_hs) = sha2_comp_config.compute_witness(
                    &padded_inputs[round_idx * one_round_size..(round_idx + 1) * one_round_size],
                    last_hs,
                );
                last_hs = next_hs;
                let mut assigned_rows = Sha256AssignedRows::<F>::new(
                    n_round * Sha256CompressionConfig::<F>::ROWS_PER_BLOCK,
                );
                sha2_comp_config.assign_witness(region, &witness, &mut assigned_rows)?;
                let assigned_h_ins = assigned_rows.get_h_ins();
                debug_assert_eq!(assigned_h_ins.len(), 1);
                let assigned_h_outs = assigned_rows.get_h_outs();
                debug_assert_eq!(assigned_h_outs.len(), 1);
                let assigned_input_words = assigned_rows.get_input_words();
                debug_assert_eq!(assigned_input_words.len(), 1);
                let assigned_input_word_at_round = &assigned_input_bytes
                    [round_idx * one_round_size..(round_idx + 1) * one_round_size];
                // 1. Constrain input bytes.
                for word_idx in 0..16 {
                    let assigned_input_u32 =
                        &assigned_input_word_at_round[4 * word_idx..4 * (word_idx + 1)];
                    let mut sum = ctx.load_zero();
                    for (idx, assigned_byte) in assigned_input_u32.iter().enumerate() {
                        sum = gate.mul_add(
                            ctx,
                            QuantumCell::Existing(assigned_byte.clone()),
                            QuantumCell::Constant(F::from(1u64 << (8 * idx))),
                            QuantumCell::Existing(sum.clone()),
                        );
                    }
                    // ctx.constrain_equal(&sum, &assigned_input_words[0][word_idx]);
                }
                // 2. Constrain the previous h_out == current h_in.
                for (h_out, h_in) in assigned_last_hs_vec[assigned_last_hs_vec.len() - 1]
                    .iter()
                    .zip(assigned_h_ins[0].iter())
                {
                    // ctx.constrain_equal(h_out, h_in);
                }
                // 3. Push the current h_out to assigned_last_hs_vec.
                assigned_last_hs_vec.push(self.upload_assigned_cells(
                    assigned_h_outs[0].iter(),
                    assigned_advices,
                    0,
                    witness_gen_only,
                ));
            }
        }

        let zero = ctx.load_zero();
        let mut output_h_out = vec![zero; 8];
        for (n_round, assigned_h_out) in assigned_last_hs_vec.into_iter().enumerate() {
            let selector = gate.is_equal(
                ctx,
                QuantumCell::Constant(F::from(n_round as u64)),
                QuantumCell::Existing(assigned_num_round),
            );
            for i in 0..8 {
                output_h_out[i] = gate.select(
                    ctx,
                    QuantumCell::Existing(assigned_h_out[i].clone()),
                    QuantumCell::Existing(output_h_out[i].clone()),
                    QuantumCell::Existing(selector.clone()),
                )
            }
        }
        let output_digest_bytes = output_h_out
            .into_iter()
            .flat_map(|assigned_word| {
                let be_bytes = assigned_word.value().get_lower_32().to_be_bytes().to_vec();
                let assigned_bytes = (0..4)
                    .map(|idx| {
                        let assigned = ctx.load_witness(F::from(be_bytes[idx] as u64));
                        range.range_check(ctx, assigned.clone(), 8);
                        assigned
                    })
                    .collect::<Vec<AssignedValue<F>>>();
                let mut sum = ctx.load_zero();
                for (idx, assigned_byte) in assigned_bytes.iter().enumerate() {
                    sum = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(assigned_byte.clone()),
                        QuantumCell::Constant(F::from(1u64 << (24 - 8 * idx))),
                        QuantumCell::Existing(sum.clone()),
                    );
                }
                ctx.constrain_equal(&assigned_word, &sum);
                assigned_bytes
            })
            .collect::<Vec<AssignedValue<F>>>();
        let result = AssignedHashResult {
            input_len: assigned_input_byte_size,
            input_bytes: assigned_input_bytes,
            output_bytes: output_digest_bytes,
        };
        Ok(result)
    }

    pub fn range(&self) -> &RangeChip<F> {
        &self.range
    }

    fn upload_assigned_cells(
        &self,
        assigned_cells: impl IntoIterator<Item = &'a AssignedCell<F, F>>,
        assigned_advices: &mut HashMap<(usize, usize), (circuit::Cell, usize)>,
        offset: usize,
        witness_gen_only: bool,
    ) -> Vec<AssignedValue<F>> {
        assigned_cells
            .into_iter()
            .enumerate()
            .map(|(i, assigned_cell)| {
                let value = value_to_option(assigned_cell.value())
                    .map(|v| Assigned::Trivial(*v))
                    .unwrap_or_else(|| Assigned::Trivial(F::zero())); // for keygen

                let aval = AssignedValue {
                    value,
                    cell: (!witness_gen_only).then_some(ContextCell {
                        context_id: SHA256_CONTEXT_ID,
                        offset: offset + i,
                    }),
                };
                if !witness_gen_only {
                    // we set row_offset = usize::MAX because you should never be directly using lookup on such a cell
                    assigned_advices.insert(
                        (SHA256_CONTEXT_ID, offset + i),
                        (assigned_cell.cell(), usize::MAX),
                    );
                }
                aval
            })
            .collect_vec()
    }
}

#[cfg(test)]
mod test {
    use std::{cell::RefCell, marker::PhantomData};

    use super::*;
    use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
    use halo2_base::{
        gates::{
            builder::{GateThreadBuilder, KeygenAssignments},
            range::RangeStrategy,
        },
        halo2_proofs::{
            circuit::{Cell, Layouter, Region, SimpleFloorPlanner},
            dev::MockProver,
            halo2curves::bn256::Fr,
            plonk::{Circuit, ConstraintSystem, Instance},
        },
    };

    use num_bigint::RandomBits;
    use rand::rngs::OsRng;
    use rand::{thread_rng, Rng};

    #[derive(Debug, Clone)]
    struct TestConfig<F: Field> {
        sha256_comp_configs: Vec<Sha256CompressionConfig<F>>,
        pub max_byte_size: usize,
        range: RangeConfig<F>,
        hash_column: Column<Instance>,
    }

    struct TestCircuit<F: Field> {
        builder: RefCell<GateThreadBuilder<F>>,
        range: RangeChip<F>,
        test_input: Vec<u8>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_comp_configs = (0..Self::NUM_COMP)
                .map(|_| Sha256CompressionConfig::configure(meta))
                .collect();
            let range = RangeConfig::configure(
                meta,
                RangeStrategy::Vertical,
                &[Self::NUM_ADVICE],
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                Self::K,
            );
            let hash_column = meta.instance_column();
            meta.enable_equality(hash_column);
            Self::Config {
                sha256_comp_configs,
                max_byte_size: Self::MAX_BYTE_SIZE,
                range,
                hash_column,
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
                config.sha256_comp_configs,
                &self.range,
                config.max_byte_size,
            );

            let assigned_hash_cells = layouter.assign_region(
                || "dynamic sha2 test",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(vec![]);
                    }
                    let builder = &mut self.builder.borrow_mut();
                    let witness_gen_only = builder.witness_gen_only();
                    let ctx = builder.main(0);

                    let mut assigned_advices = HashMap::new();
                    let result = sha256.digest(
                        &self.test_input,
                        ctx,
                        &mut region,
                        &mut assigned_advices,
                        witness_gen_only,
                    )?;
                    let assigned_hash = result.output_bytes;

                    let _ = builder.assign_all(
                        &config.range.gate,
                        &config.range.lookup_advice,
                        &config.range.q_lookup,
                        &mut region,
                        KeygenAssignments {
                            assigned_advices: assigned_advices.clone(),
                            ..Default::default()
                        },
                    );

                    Ok(assigned_hash.into_iter().map(|v| v.cell).collect())
                },
            )?;
            // for (idx, hash) in assigned_hash_cells.into_iter().enumerate() {
            //     layouter.constrain_instance(hash, config.hash_column, idx)?;
            // }
            Ok(())
        }
    }

    impl<F: Field> TestCircuit<F> {
        const MAX_BYTE_SIZE: usize = 10240;
        const NUM_ADVICE: usize = 50;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 12;
        const NUM_COMP: usize = 10;
        const K: usize = 13;
    }

    #[test]
    fn test_sha256_correct1() {
        let k = 13;

        // Test vector: "abc"
        let test_input = vec!['a' as u8, 'b' as u8, 'c' as u8];

        let range = RangeChip::default(TestCircuit::<Fr>::LOOKUP_BITS);
        let builder = GateThreadBuilder::new(false);
        let circuit = TestCircuit::<Fr> {
            builder: RefCell::new(builder),
            range,
            test_input,
            _f: PhantomData,
        };
        let test_output: [u8; 32] = [
            0b10111010, 0b01111000, 0b00010110, 0b10111111, 0b10001111, 0b00000001, 0b11001111,
            0b11101010, 0b01000001, 0b01000001, 0b01000000, 0b11011110, 0b01011101, 0b10101110,
            0b00100010, 0b00100011, 0b10110000, 0b00000011, 0b01100001, 0b10100011, 0b10010110,
            0b00010111, 0b01111010, 0b10011100, 0b10110100, 0b00010000, 0b11111111, 0b01100001,
            0b11110010, 0b00000000, 0b00010101, 0b10101101,
        ];
        let test_output = test_output.map(|val| Fr::from(val as u64)).to_vec();
        let public_inputs = vec![test_output];

        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // #[test]
    // fn test_sha256_correct2() {
    //     let k = 13;

    //     // Test vector: "0x0"
    //     let test_input = vec![0u8];

    //     let circuit = TestCircuit::<Fr> {
    //         test_input,
    //         _f: PhantomData,
    //     };
    //     let test_output: [u8; 32] = [
    //         0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78,
    //         0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
    //         0x17, 0xaf, 0xa0, 0x1d,
    //     ];
    //     let test_output = test_output.map(|val| Fr::from_u128(val as u128)).to_vec();
    //     let public_inputs = vec![test_output];

    //     let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }

    // #[test]
    // fn test_sha256_correct3() {
    //     let k = 13;

    //     let test_input = vec![0x1; 56];

    //     let circuit = TestCircuit::<Fr> {
    //         test_input,
    //         _f: PhantomData,
    //     };
    //     let test_output: [u8; 32] = [
    //         0x51, 0xe1, 0x4a, 0x91, 0x36, 0x80, 0xf2, 0x4c, 0x85, 0xfe, 0x3b, 0x0e, 0x2e, 0x5b,
    //         0x57, 0xf7, 0x20, 0x2f, 0x11, 0x7b, 0xb2, 0x14, 0xf8, 0xff, 0xdd, 0x4e, 0xa0, 0xf4,
    //         0xe9, 0x21, 0xfd, 0x52,
    //     ];
    //     let test_output = test_output.map(|val| Fr::from_u128(val as u128)).to_vec();
    //     let public_inputs = vec![test_output];

    //     let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }
}
