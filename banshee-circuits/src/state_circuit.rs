use crate::{
    table::{LookupTable, StateTable, SHA256Table, sha256_table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerklePath},
};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
};
use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::iter;


#[derive(Clone, Debug)]
struct PathChipConfig {
    s_path: Column<Advice>,
    sibling: Column<Advice>,
    path: Column<Advice>,
    hash_type: Column<Advice>,
    value: Column<Advice>,
    sha256_table: SHA256Table,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct PathChip<'a, F: Field> {
    offset: usize,
    config: PathChipConfig,
    data: &'a MerklePath<F>,
}

impl<F: Field> Chip<F> for PathChip<'_, F> {
    type Config = PathChipConfig;
    type Loaded = MerklePath<F>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'a, F: Field> PathChip<'a, F> {
    fn configure(
        meta: &mut ConstraintSystem<F>, 
        sha256_table: SHA256Table,
        config: PathChipConfig,
    ) -> <Self as Chip<F>>::Config {
        meta.lookup_any("tree node hash", |meta| {
            let s_path = meta.query_advice(config.s_path, Rotation::cur());

            let path_bit = meta.query_advice(config.path, Rotation::cur());
            let val_col = meta.query_advice(config.value, Rotation::cur());
            let sibling_col = meta.query_advice(config.sibling, Rotation::cur());
            let node_hash = meta.query_advice(config.value, Rotation::prev());

            sha256_table.build_lookup(
                meta,
                s_path,
                path_bit.clone() * (sibling_col.clone() - val_col.clone()) + val_col.clone(), // path_bit == 1 ? sibling_col : val_col
                path_bit * (val_col - sibling_col.clone()) + sibling_col, // path_bit == 1 ? val_col : sibling_col
                node_hash,
            )
        });

        meta.lookup_any("tree leaf hash", |meta| {
            let s_leaf = meta.query_advice(config.s_path, Rotation::cur());

            let key_immediate = meta.query_advice(key_immediate, Rotation::cur());
            let leaf_val = meta.query_advice(val, Rotation::cur());
            let leaf_hash = meta.query_advice(val, Rotation::prev());
            hash_table.build_lookup(meta, s_leaf, key_immediate, leaf_val, leaf_hash)
        });

        config
    }
}
