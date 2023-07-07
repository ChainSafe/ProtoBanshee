use typenum::{
    Exp, Prod, Unsigned, U10, U100, U2, U32, U40, U41, U43, U46, U5, U50, U512, U8, U9,
};
use core::fmt::Debug;

pub trait Spec: 'static + Default + Debug {
    const MAX_VALIDATORS: usize;
    const VALIDATOR_0_G_INDEX: usize;
    const CHUNKS_PER_VALIDATOR: usize;
    const USED_CHUNKS_PER_VALIDATOR: usize;
    const TREE_DEPTH: usize; 
    const PUBKEYS_LEVEL: usize;
    const VALIDATORS_LEVEL: usize;
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {

    const MAX_VALIDATORS: usize = 100;
    const VALIDATOR_0_G_INDEX: usize = 32;
    const CHUNKS_PER_VALIDATOR: usize = 100;
    const USED_CHUNKS_PER_VALIDATOR: usize = 8;
    const TREE_DEPTH: usize = 46;
    const PUBKEYS_LEVEL: usize = 10;
    const VALIDATORS_LEVEL: usize = Self::PUBKEYS_LEVEL - 1;
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const MAX_VALIDATORS: usize = 1099511627776;
    const VALIDATOR_0_G_INDEX: usize = 94557999988736;
    const CHUNKS_PER_VALIDATOR: usize = 100;
    const USED_CHUNKS_PER_VALIDATOR: usize = 8;
    const TREE_DEPTH: usize = 50;
    // TODO: calculate and verify the pubkeys level for mainnet
    const PUBKEYS_LEVEL: usize = 40;
    const VALIDATORS_LEVEL: usize = Self::PUBKEYS_LEVEL - 1;
}