use std::collections::HashMap;

use eth_types::Field;
use gadgets::util::rlc;
use itertools::Itertools;
// //! Gadget and chips for the [SHA-256] hash function.
// //!
// //! [SHA-256]: https://tools.ietf.org/html/rfc6234
use crate::{
    sha256_circuit::{
        sha256_bit::{sha256, ShaRow},
        util::Sha256AssignedRows,
    },
    witness::HashInput,
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

use super::Sha256CircuitConfig;

const Sha256BitChipRowPerRound: usize = 72;
const BLOCK_BYTE: usize = 64;
const DIGEST_BYTE: usize = 32;
const SHA256_CONTEXT_ID: usize = usize::MAX;

#[derive(Debug, Clone)]
pub struct AssignedHashResult<F: Field> {
    pub input_len: AssignedValue<F>,
    pub input_bytes: Vec<AssignedValue<F>>,
    pub output_bytes: [AssignedValue<F>; 32],
}

pub struct Sha256Chip<'a, F: Field> {
    sha256_bit_config: Sha256CircuitConfig<F>,
    pub max_input_size: usize,
    range: &'a RangeChip<F>,
    rnd: F,
}

impl<'a, F: Field> Sha256Chip<'a, F> {
    pub fn new(
        sha256_bit_config: Sha256CircuitConfig<F>,
        range: &'a RangeChip<F>,
        max_byte_size: usize,
        rnd: F,
    ) -> Self {
        Self {
            sha256_bit_config,
            max_input_size: max_byte_size,
            range,
            rnd,
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
        let rnd = QuantumCell::Constant(self.rnd.clone());
        let input_byte_size = input.len();
        let max_byte_size = self.max_input_size;
        assert!(input_byte_size <= max_byte_size);
        let range = &self.range;
        let gate = &range.gate;

        assert!(input.len() <= self.max_input_size);
        let mut assigned_rows = Sha256AssignedRows::default();
        let assigned_hash_bytes = self.sha256_bit_config.digest_with_region(
            region,
            HashInput::Single(input.to_vec()),
            &mut assigned_rows,
        )?;
        let assigned_output =
            assigned_hash_bytes.map(|b| ctx.load_witness(*value_to_option(b.value()).unwrap()));

        let input_byte_size_with_9 = input_byte_size + 9;
        let one_round_size = BLOCK_BYTE;
        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let zero_padding_byte_size = padded_size - input_byte_size - 9;
        let max_round = max_byte_size / one_round_size;
        let remaining_byte_size = max_byte_size - padded_size;
        assert_eq!(
            remaining_byte_size,
            one_round_size * (max_round - num_round)
        );

        let mut assign_byte = |byte: u8| ctx.load_witness(F::from(byte as u64));
        let mut assigned_input = vec![];
        for byte in input.iter() {
            //range.range_check(ctx, &assigned, 8);
            assigned_input.push(assign_byte(*byte));
        }
        assigned_input.push(assign_byte(0x80));
        for _ in 0..zero_padding_byte_size {
            assigned_input.push(assign_byte(0u8));
        }
        let mut input_len_bytes = [0; 8];
        let le_size_bytes = (8 * input_byte_size).to_le_bytes();
        input_len_bytes[0..le_size_bytes.len()].copy_from_slice(&le_size_bytes);
        for byte in input_len_bytes.iter().rev() {
            assigned_input.push(assign_byte(*byte));
        }
        assert_eq!(assigned_input.len(), num_round * one_round_size);
        for _ in 0..remaining_byte_size {
            assigned_input.push(assign_byte(0u8));
        }
        assert_eq!(assigned_input.len(), max_byte_size);
        for &assigned in assigned_input.iter() {
            range.range_check(ctx, assigned, 8);
        }

        let zero = ctx.load_zero();
        let mut full_input_len = zero.clone();

        let mut offset = 0;
        for round_idx in 0..max_round {
            let input_len = self.assigned_cell2value(ctx, &assigned_rows.input_len[round_idx]);

            let input_rlcs = {
                let input_rlc_cells =
                    assigned_rows.input_rlc[16 * round_idx..16 * (round_idx + 1)].iter();
                self.upload_assigned_cells(
                    input_rlc_cells,
                    &mut offset,
                    assigned_advices,
                    witness_gen_only,
                )
            };

            let padding_selectors = assigned_rows.padding_selectors
                [16 * round_idx..16 * (round_idx + 1)]
                .into_iter()
                .map(|cells| {
                    self.upload_assigned_cells(
                        cells,
                        &mut offset,
                        assigned_advices,
                        witness_gen_only,
                    )
                    .try_into()
                    .unwrap()
                })
                .collect::<Vec<[_; 4]>>();

            let [is_output_enabled, output_rlc]: [_; 2] = self
                .upload_assigned_cells(
                    [
                        &assigned_rows.is_final[round_idx],
                        &assigned_rows.output_words[round_idx],
                    ],
                    &mut offset,
                    assigned_advices,
                    witness_gen_only,
                )
                .try_into()
                .unwrap();

            full_input_len = {
                let muled = gate.mul(ctx, is_output_enabled, input_len);
                gate.add(ctx, full_input_len, muled)
            };

            let mut sum = zero.clone();
            for word_idx in 0..16 {
                let offset_in = 64 * round_idx + 4 * word_idx;
                let assigned_input_u32 = &assigned_input[offset_in + 0..offset_in + 4];

                for (idx, &assigned_byte) in assigned_input_u32.iter().enumerate() {
                    let tmp = gate.mul_add(ctx, sum, rnd, assigned_byte);

                    sum = gate.select(ctx, sum, tmp, padding_selectors[word_idx][idx]);
                }
                ctx.constrain_equal(&sum, &input_rlcs[word_idx]);
            }

            let hash_rlc = rlc::assigned_value(&assigned_output, &rnd, gate, ctx);
            ctx.constrain_equal(&hash_rlc, &output_rlc);
        }
        for &byte in assigned_output.iter() {
            range.range_check(ctx, byte, 8);
        }

        Ok(AssignedHashResult {
            input_len: full_input_len,
            input_bytes: assigned_input,
            output_bytes: assigned_output,
        })
    }

    pub fn range(&self) -> &RangeChip<F> {
        &self.range
    }

    fn assigned_cell2value(
        &self,
        ctx: &mut Context<F>,
        assigned_cell: &AssignedCell<F, F>,
    ) -> AssignedValue<F> {
        let assigned_value = ctx.load_witness(*value_to_option(assigned_cell.value()).unwrap());
        // ctx.region
        //     .constrain_equal(assigned_cell.cell(), assigned_value.cell())?;
        assigned_value
    }

    fn upload_assigned_cells(
        &self,
        assigned_cells: impl IntoIterator<Item = &'a AssignedCell<F, F>>,
        offset: &mut usize,
        assigned_advices: &mut HashMap<(usize, usize), (circuit::Cell, usize)>,
        witness_gen_only: bool,
    ) -> Vec<AssignedValue<F>> {
        let assigned_values = assigned_cells
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
                        offset: *offset + i,
                    }),
                };
                if !witness_gen_only {
                    // we set row_offset = usize::MAX because you should never be directly using lookup on such a cell
                    assigned_advices.insert(
                        (SHA256_CONTEXT_ID, *offset + i),
                        (assigned_cell.cell(), usize::MAX),
                    );
                }
                aval
            })
            .collect_vec();
        *offset += assigned_values.len();
        assigned_values
    }
}

#[cfg(test)]
mod test {
    use std::{cell::RefCell, marker::PhantomData};

    use crate::table::SHA256Table;
    use crate::util::SubCircuitConfig;

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
        sha256_config: Sha256CircuitConfig<F>,
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
            let sha_table = SHA256Table::construct(meta);
            let sha256_configs = Sha256CircuitConfig::<F>::new(meta, sha_table);
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
                sha256_config: sha256_configs,
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
                config.sha256_config,
                &self.range,
                config.max_byte_size,
                Sha256CircuitConfig::fixed_challenge(),
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
        const MAX_BYTE_SIZE: usize = 64;
        const NUM_ADVICE: usize = 5;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 4;
        const LOOKUP_BITS: usize = 8;
        const K: usize = 13;
    }

    #[test]
    fn test_sha256_correct1() {
        let k = 12;

        let test_input = vec![1; 32];

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
        prover.assert_satisfied();
    }
}
