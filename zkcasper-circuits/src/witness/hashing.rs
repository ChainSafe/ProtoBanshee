use banshee_preprocessor::util::pad_to_ssz_chunk;
use itertools::Itertools;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HashInput<T> {
    Single(Vec<T>, bool),
    TwoToOne {
        left: Vec<T>,
        right: Vec<T>,
        is_rlc: [bool; 2],
    },
}

impl<T: Clone> HashInput<T> {
    pub fn is_rlc(&mut self, val: bool) {
        match self {
            HashInput::Single(_, ref mut rlc) => *rlc = val,
            HashInput::TwoToOne { .. } => unimplemented!("use is_two_rlc for HashInput::TwoToOne"),
        }
    }

    pub fn is_two_rlc(&mut self, left: bool, right: bool) {
        match self {
            HashInput::TwoToOne { is_rlc: rlc, .. } => {
                rlc[0] = left;
                rlc[1] = right;
            }
            HashInput::Single(_, ref mut rlc) => unimplemented!("use is_rlc for HashInput::Single"),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            HashInput::Single(input, _) => input.len(),
            HashInput::TwoToOne { left, right, .. } => left.len() + right.len(),
        }
    }

    pub fn to_vec(self) -> Vec<T> {
        match self {
            HashInput::Single(input, _) => input,
            HashInput::TwoToOne { left, right, .. } => {
                let mut result = left;
                result.extend(right);
                result
            }
        }
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInput<B> {
        match self {
            HashInput::Single(input, is_rlc) => {
                HashInput::Single(input.into_iter().map(f).collect(), is_rlc)
            }
            HashInput::TwoToOne {
                left,
                right,
                is_rlc,
            } => {
                let left_size = left.len();
                let mut all = left
                    .into_iter()
                    .chain(right.into_iter())
                    .map(f)
                    .collect_vec();
                let right = all.split_off(left_size);

                HashInput::TwoToOne {
                    left: all,
                    right,
                    is_rlc,
                }
            }
        }
    }
}

impl From<&[u8]> for HashInput<u8> {
    fn from(input: &[u8]) -> Self {
        HashInput::Single(input.to_vec(), input.len() >= 32)
    }
}

impl From<Vec<u8>> for HashInput<u8> {
    fn from(input: Vec<u8>) -> Self {
        let is_rlc = input.len() >= 32;
        HashInput::Single(input, is_rlc)
    }
}

impl From<(&[u8], &[u8])> for HashInput<u8> {
    fn from((left, right): (&[u8], &[u8])) -> Self {
        HashInput::TwoToOne {
            left: left.to_vec(),
            right: right.to_vec(),
            is_rlc: [left.len() >= 32, right.len() >= 32],
        }
    }
}

impl From<u64> for HashInput<u8> {
    fn from(input: u64) -> Self {
        HashInput::Single(pad_to_ssz_chunk(&input.to_le_bytes()), false)
    }
}

impl From<usize> for HashInput<u8> {
    fn from(input: usize) -> Self {
        HashInput::Single(pad_to_ssz_chunk(&input.to_le_bytes()), false)
    }
}
