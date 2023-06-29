import { 
    BeaconState
} from "@lodestar/types/phase0"

use typenum::{
    U1, U10, U100, U31, U41, U43, U5, U8, U9,
};

pub trait Spec: 'static + Default + Debug {
    type MaxValidators: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type Validator0GIndex: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ChunksPerValidator: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type UsedChunksPerValidator: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type TreeDepth: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PubkeysLevel: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    // type ValidatorsLevel: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn max_validators() -> usize {
        Self::MaxValidators::to_usize()
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

    fn pubkeys_level() -> usize {
        BeaconState.getPathInfo(["validators", 0, "pubkey"]) * 2n;
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
    type MaxValidators = U100;
    type Validator0GIndex = U100;
    type ChunksPerValidator = U8;
    type UsedChunksPerValidator = U5;
    type TreeDepth = U10;
    type PubkeysLevel = U10;
}

pub struct Mainnet;

impl Spec for Mainnet {
    // (2**40)=1099511627776
    type MaxValidators = Prod<EXP<U2>, U40>;
    // 94557999988736
    type Validator0GIndex = Prod<Exp<U2, U41>, U43>;
    type ChunksPerValidator = U9;
    type UsedChunksPerValidator = U5;
    type TreeDepth = U10;
    type PubkeysLevel = U10;
}