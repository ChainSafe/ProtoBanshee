use std::hash::Hash;

use banshee_preprocessor::util::pad_to_ssz_chunk;
use eth_types::Field;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HashInput<T, U = T> {
    Single(HashInputRaw<T>),
    TwoToOne(HashInputRaw<T>, HashInputRaw<U>),
}

impl<T: Clone> HashInput<T> {
    pub fn len(&self) -> usize {
        match self {
            HashInput::Single(inner) => inner.bytes.len(),
            HashInput::TwoToOne(left, right) => left.bytes.len() + right.bytes.len(),
        }
    }

    pub fn to_vec(self) -> Vec<T> {
        match self {
            HashInput::Single(inner) => inner.bytes,
            HashInput::TwoToOne(left, right) => {
                let mut result = left.bytes;
                result.extend(right.bytes);
                result
            }
        }
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInput<B> {
        match self {
            HashInput::Single(inner) => HashInput::Single(HashInputRaw {
                bytes: inner.bytes.into_iter().map(f).collect(),
                is_rlc: inner.is_rlc,
            }),
            HashInput::TwoToOne(left, right) => {
                let left_size = left.bytes.len();
                let mut all = left
                    .bytes
                    .into_iter()
                    .chain(right.bytes.into_iter())
                    .map(f)
                    .collect_vec();
                let remainer = all.split_off(left_size);
                let left = HashInputRaw {
                    bytes: all,
                    is_rlc: left.is_rlc,
                };
                let right = HashInputRaw {
                    bytes: remainer,
                    is_rlc: right.is_rlc,
                };

                HashInput::TwoToOne(left, right)
            }
        }
    }

    pub fn with_is_rlc(mut self, val: bool) -> Self {
        match self {
            HashInput::Single(ref mut inner) => inner.is_rlc = val,
            HashInput::TwoToOne { .. } => unimplemented!("use is_two_rlc for HashInput::TwoToOne"),
        }

        self
    }

    pub fn with_two_is_rlc(mut self, left: bool, right: bool) -> Self {
        match self {
            HashInput::TwoToOne(ref mut l, ref mut r) => {
                l.is_rlc = left;
                r.is_rlc = right;
            }
            HashInput::Single(_) => unimplemented!("use HashInput::is_rlc for HashInput::Single"),
        }

        self
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HashInputRaw<T> {
    pub bytes: Vec<T>,
    pub is_rlc: bool,
}

impl<T> HashInputRaw<T> {
    pub fn new(bytes: Vec<T>, is_rlc: bool) -> Self {
        Self { bytes, is_rlc }
    }
}

impl HashInputRaw<u8> {
    pub fn assign_with_ctx<F: Field>(&self, ctx: &mut Context<F>) -> HashInputRaw<AssignedValue<F>> {
        let bytes = self
            .bytes
            .into_iter()
            .map(|b| ctx.load_witness(F::from(b as u64)))
            .collect();
        HashInputRaw {
            bytes,
            is_rlc: self.is_rlc,
        }
    }
}

impl<I: Into<HashInputRaw<u8>>> From<I> for HashInput<u8> {
    fn from(input: I) -> Self {
        HashInput::Single(input.into())
    }
}

impl<IL: Into<HashInputRaw<u8>>, IR: Into<HashInputRaw<u8>>> From<(IL, IR)> for HashInput<u8> {
    fn from(input: (IL, IR)) -> Self {
        let left = input.0.into();
        let right = input.1.into();
        HashInput::TwoToOne(left, right)
    }
}

impl From<&[u8]> for HashInputRaw<u8> {
    fn from(input: &[u8]) -> Self {
        HashInputRaw {
            bytes: input.to_vec(),
            is_rlc: input.len() >= 32,
        }
    }
}

impl From<Vec<u8>> for HashInputRaw<u8> {
    fn from(input: Vec<u8>) -> Self {
        let is_rlc = input.len() >= 32;
        HashInputRaw {
            bytes: input,
            is_rlc,
        }
    }
}

impl From<u64> for HashInputRaw<u8> {
    fn from(input: u64) -> Self {
        HashInputRaw {
            bytes: pad_to_ssz_chunk(&input.to_le_bytes()),
            is_rlc: false,
        }
    }
}

impl From<usize> for HashInputRaw<u8> {
    fn from(input: usize) -> Self {
        HashInputRaw {
            bytes: pad_to_ssz_chunk(&input.to_le_bytes()),
            is_rlc: false,
        }
    }
}

impl<F: Field, I: IntoIterator<Item = AssignedValue<F>>> From<I>
    for HashInputRaw<AssignedValue<F>>
{
    fn from(input: I) -> Self {
        let bytes = input.into_iter().collect_vec();
        HashInputRaw {
            is_rlc: bytes.len() >= 32,
            bytes: bytes,
        }
    }
}
