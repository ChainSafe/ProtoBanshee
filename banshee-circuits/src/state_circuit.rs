use crate::MAX_VALIDATORS;

pub mod cell_manager;
pub mod constraint_builder;

use cell_manager::CellManager;
use constraint_builder::ConstraintBuilder;

use crate::{
    table::{LookupTable, StateTable, SHA256Table, sha256_table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace}, gadget::IsEqualGadget,
};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig}, util::Expr,
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

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
// pub const TREE_MAX_LEAVES: usize = MAX_VALIDATORS * CHUNKS_PER_VALIDATOR; 
// pub const TREE_DEPTH: usize = 7; // ceil(log2(TREE_MAX_LEAVES))
// pub const TREE_LEVEL_COLUMNS: usize = 2;

pub const PUBKEYS_LEVEL: usize = 10;


#[derive(Clone, Debug)]
struct PathChipConfig<F> {
    depth: Column<Advice>,
    sibling: Column<Advice>,
    sibling_index: Column<Advice>,
    node: Column<Advice>,
    index: Column<Advice>,
    is_leaf: Column<Advice>,
    // is_left: Column<Advice>,
    parent: Column<Advice>,
    parent_index: Column<Advice>,
    sha256_table: SHA256Table,
    _f: std::marker::PhantomData<F>,
    // tree: [CellManager<F>; TREE_DEPTH],
}

/// chip for verify Merkle-multi proof
struct PathChip<'a, F: Field> {
    offset: usize,
    config: PathChipConfig<F>,
    data: &'a MerkleTrace<F>,
}

impl<F: Field> Chip<F> for PathChip<'_, F> {
    type Config = PathChipConfig<F>;
    type Loaded = MerkleTrace<F>;

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
        validators_num: usize
    ) -> <Self as Chip<F>>::Config {
        let depth = meta.advice_column();
        let sibling = meta.advice_column();
        let sibling_index = meta.advice_column();
        let node = meta.advice_column();
        let index = meta.advice_column();
        let is_leaf = meta.advice_column();
        let parent = meta.advice_column();
        let parent_index = meta.advice_column();

        let storage_column = meta.advice_column();
        // let tree = [
        //     TreeLevel::new(meta, validators_num, 9, 0),
        // ];

        let config = PathChipConfig::<F> {
            depth,
            sibling,
            sibling_index,
            node,
            index,
            is_leaf,
            parent,
            parent_index,
            sha256_table,
            _f: std::marker::PhantomData,
        };

        let N = 100; // TODO change cell manager 
        let cell_manager: CellManager<F> = CellManager::new(meta, N, &[storage_column], 0);
        let mut constraint_builder = ConstraintBuilder::new(cell_manager);


        meta.lookup_any("public keys level", |meta| {
            let depth: Expression<F> = meta.query_advice(config.depth, Rotation::cur());
            let s_level: Expression<F> = IsEqualGadget::construct(&mut constraint_builder, depth, PUBKEYS_LEVEL.expr()).expr();

            let sibling: Expression<F> = meta.query_advice(config.sibling, Rotation::cur());
            let node: Expression<F> = meta.query_advice(config.node, Rotation::cur());
            let parent: Expression<F> = meta.query_advice(config.node, Rotation::cur()); // TODO Rotation::?

            sha256_table.build_lookup(
                meta,
                s_level,
                node,
                sibling,
                node_hash,
            )
        });

        config
    }
}
