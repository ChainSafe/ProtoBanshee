pub mod table;
pub mod witness;
pub mod vs_circuit;
pub mod state_circuit;
pub mod gadget;
pub(crate) mod util;


pub const MAX_VALIDATORS: usize = 100;

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;
