use itertools::Itertools;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HashInput<T> {
    Single(Vec<T>),
    TwoToOne {
        left: Vec<T>,
        right: Vec<T>,
        is_rlc: [bool; 2],
    },
}

impl<T: Clone> HashInput<T> {
    pub fn len(&self) -> usize {
        match self {
            HashInput::Single(input) => input.len(),
            HashInput::TwoToOne { left, right, .. } => left.len() + right.len(),
        }
    }

    pub fn to_vec(self) -> Vec<T> {
        match self {
            HashInput::Single(input) => input,
            HashInput::TwoToOne { left, right, .. } => {
                let mut result = left;
                result.extend(right);
                result
            }
        }
    }

    pub fn map<B, F: FnMut(T) -> B>(self, f: F) -> HashInput<B> {
        match self {
            HashInput::Single(input) => HashInput::Single(input.into_iter().map(f).collect()),
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
