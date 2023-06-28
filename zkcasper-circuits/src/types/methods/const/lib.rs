use typenum::{
    U1, U10, U100, U31, U32, U5, U8,
};

pub trait Spec: 'static + Default + Debug {
    type MaxValidators: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type Validator0GIndex: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxNBytesInteger: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type NBytesU64: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ChunksPerValidator: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type UsedChunksPerValidator: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type TreeDepth: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type TreeLevelAuxColumn: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PubkeysLevel: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    // type ValidatorsLevel: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn max_validators() -> usize {
        Self::MaxValidators::to_usize()
    }

    fn validator0_gindex() -> usize {
        Self::Validator0GIndex::to_usize()
    }

    fn max_n_bytes_integer() -> usize {
        Self::MaxNBytesInteger::to_usize()
    }

    fn n_bytes_u64() -> usize {
        Self::NBytesU64::to_usize()
    }

    fn chunks_per_validator() -> usize {
        Self::ChunksPerValidator::to_usize()
    }

    fn used_chunks_per_validator() -> usize {
        Self::UsedChunksPerValidator::to_usize()
    }

    fn tree_depth() -> usize {
        Self::TreeDepth::to_usize()
    }

    fn tree_level_aux_column() -> usize {
        Self::TreeLevelAuxColumn::to_usize()
    }

    fn pubkeys_level() -> usize {
        Self::PubkeysLevel::to_usize()
    }

    fn validators_level() -> usize {
        if Self::PubkeysLevel::to_usize() <= 0 {
            panic!("validators_level: negative usize")
        } else {
            Self::PubkeysLevel::to_usize() - 1;
        }
    }

}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Test;

impl Spec for Test {
    type MaxValidators = U32;
    type Validator0GIndex = U100;
    type MaxNBytesInteger = U31;
    type NBytesU64 = U8;
    type ChunksPerValidator = U8;
    type UsedChunksPerValidator = U5;
    type TreeDepth = U10;
    type TreeLevelAuxColumn = U1;
    type PubkeysLevel = U10;
}