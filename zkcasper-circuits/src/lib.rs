#![feature(generic_const_exprs)]
#![feature(associated_type_bounds)]
#![feature(inherent_associated_types)]
pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod aggregation_circuit;
pub mod aggregation_circuit_copy;
pub mod sha256_circuit;
pub mod state_circuit;
pub mod super_circuit;
pub mod validators_circuit;

// TODO: impl as Spec trait
// example: https://github.com/ChainSafe/Zipline/blob/main/finality-client/libs/zipline-spec/src/lib.rs

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;

pub trait Spec {
    const VALIDATOR_REGISTRY_LIMIT: usize;
}

struct MainnetSpec;

impl Spec for MainnetSpec {
    const VALIDATOR_REGISTRY_LIMIT: usize = 100;
}
