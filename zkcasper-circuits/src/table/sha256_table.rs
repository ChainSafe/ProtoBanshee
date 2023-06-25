use super::*;
use crate::{util::{Challenges, rlc}, witness::HashInput};
use itertools::Itertools;
use sha2::Digest;

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct SHA256Table {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array first input as `RLC(input[i])`
    pub limbs_rlc: [Column<Advice>; 2],
    /// Byte array first input as `RLC(input[i])`
    pub input_rlc: Column<Advice>,
    /// Length of first+second inputs
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub hash_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for SHA256Table {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.limbs_rlc[0].into(),
            self.limbs_rlc[1].into(),
            self.input_rlc.into(),
            self.input_len.into(),
            self.hash_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("left_rlc"),
            String::from("right_rlc"),
            String::from("input_rlc"),
            String::from("input_len"),
            String::from("hash_rlc"),
        ]
    }
}

impl SHA256Table {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_enabled: meta.advice_column(),
            limbs_rlc: [
                meta.advice_column_in(SecondPhase),
                meta.advice_column_in(SecondPhase),
            ],
            input_rlc: meta.advice_column_in(SecondPhase),
            input_len: meta.advice_column(),
            hash_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Assign a table row for keccak table
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [Value<F>; 6],
    ) -> Result<(), Error> {
        for (&column, value) in <SHA256Table as LookupTable<F>>::advice_columns(self)
            .iter()
            .zip(values.iter())
        {
            region.assign_advice(|| format!("assign {}", offset), column, offset, || *value)?;
        }
        Ok(())
    }

    /// Generate the sha256 table assignments from a byte array input.
    pub fn assignments<F: Field>(
        input:&HashInput,
        challenge: Value<F>,
    ) -> [Value<F>; 6] {
        let (left_rlc, right_rlc, input_rlc, preimage) = match input {
            HashInput::Single(input) => {
                let input_rlc = challenge.map(|randomness| rlc::value(
                    input,
                    randomness,
                ));

                (input_rlc.clone(), Value::known(F::zero()), input_rlc, input.clone())
            },
            HashInput::MerklePair(left, right) =>  {
                let left_rlc = challenge.map(|randomness| rlc::value(
                    left,
                    randomness,
                ));
                let right_rlc = challenge.map(|randomness| rlc::value(
                    right,
                    randomness,
                ));
                let preimage = vec![left.clone(), right.clone()].concat();
                let input_rlc = challenge.map(|randomness| rlc::value(
                    &preimage,
                    randomness,
                ));

                (left_rlc, right_rlc, input_rlc, preimage)
            }
        };
       
        let input_len = F::from(preimage.len() as u64);

        let output = sha2::Sha256::digest(preimage).to_vec();
        let output_rlc = challenge.map(|randomness| rlc::value(
            &output,
            randomness,
        ));

        [
            Value::known(F::one()),
            left_rlc,
            right_rlc,
            input_rlc,
            Value::known(input_len),
            output_rlc,
        ]
    }

    /// Load sha256 table without running the full sha256 circuit.
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a HashInput> + Clone,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "sha256 table",
            |mut region| {
                let mut offset = 0;

                self.annotate_columns_in_region(&mut region);

                let sha256_table_columns = <SHA256Table as LookupTable<F>>::advice_columns(self);
                for input in inputs.clone() {
                    let row = Self::assignments(input, challenge.clone());

                    for (&column, value) in sha256_table_columns.iter().zip_eq(row) {
                        region.assign_advice(
                            || format!("sha256 table row {}", offset),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                    offset += 1;
                }
                Ok(())
            },
        )
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        enable: Expression<F>,
        fst: Expression<F>,
        snd: Expression<F>,
        hash: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        vec![
            (
                enable.clone(),
                meta.query_advice(self.is_enabled, Rotation::cur()),
            ),
            (
                enable.clone() * fst,
                meta.query_advice(self.limbs_rlc[0], Rotation::cur()),
            ),
            (
                enable.clone() * snd,
                meta.query_advice(self.limbs_rlc[1], Rotation::cur()),
            ),
            (
                enable * hash,
                meta.query_advice(self.hash_rlc, Rotation::cur()),
            ),
        ]
    }
}
