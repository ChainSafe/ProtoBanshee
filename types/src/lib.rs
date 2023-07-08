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
    const G1_FQ_BYTES: usize;
    const G1_BYTES_UNCOMPRESSED: usize;
    const LIMB_BITS: usize;
    const NUM_LIMBS: usize;
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Test;

impl Spec for Test {

    const MAX_VALIDATORS: usize = 100;
    const VALIDATOR_0_G_INDEX: usize = 32;
    const CHUNKS_PER_VALIDATOR: usize = 8;
    const USED_CHUNKS_PER_VALIDATOR: usize = 5;
    const TREE_DEPTH: usize = 10;
    const PUBKEYS_LEVEL: usize = 10;
    const VALIDATORS_LEVEL: usize = Self::PUBKEYS_LEVEL - 1;
    const G1_FQ_BYTES: usize = 32; // TODO: 48 for BLS12-381.
    const G1_BYTES_UNCOMPRESSED: usize = Self::G1_FQ_BYTES * 2;
    const LIMB_BITS: usize = 88;
    const NUM_LIMBS: usize = 3;
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Mainnet;

impl Spec for Mainnet {
    const MAX_VALIDATORS: usize = 1099511627776;
    const VALIDATOR_0_G_INDEX: usize = 94557999988736;
    const CHUNKS_PER_VALIDATOR: usize = 9;
    const USED_CHUNKS_PER_VALIDATOR: usize = 5;
    const TREE_DEPTH: usize = 47;
    // TODO: calculate and verify the pubkeys level for mainnet
    const PUBKEYS_LEVEL: usize = 49;
    const VALIDATORS_LEVEL: usize = Self::PUBKEYS_LEVEL - 1;
    const G1_FQ_BYTES: usize = 48; // TODO: 48 for BLS12-381.
    const G1_BYTES_UNCOMPRESSED: usize = Self:: G1_FQ_BYTES * 2;
    const LIMB_BITS: usize = 112;
    const NUM_LIMBS: usize = 5;
}