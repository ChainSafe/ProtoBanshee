use crate::MAX_VALIDATORS;

pub mod cell_manager;
use cell_manager::CellManager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use merkle_tree::TreeLevel;

use crate::{
    gadget::IsEqualGadget,
    table::{sha256_table, LookupTable, SHA256Table, StateTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::Expr,
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
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;

#[derive(Clone, Debug)]
pub (crate) struct PathChipConfig {
    depth: Column<Advice>,
    sibling: Column<Advice>,
    sibling_index: Column<Advice>,
    node: Column<Advice>,
    index: Column<Advice>,
    is_leaf: Column<Advice>,
    // is_left: Column<Advice>,
    parent: Column<Advice>,
    parent_index: Column<Advice>,
    aux_column: Column<Advice>,
    sha256_table: SHA256Table,
}

/// chip for verify Merkle-multi proof
pub (crate) struct PathChip<'a, F: Field> {
    offset: usize,
    config: PathChipConfig,
    data: &'a MerkleTrace<F>,
}

impl<F: Field> Chip<F> for PathChip<'_, F> {
    type Config = PathChipConfig;
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
        validators_num: usize,
    ) -> <Self as Chip<F>>::Config {
        let depth = meta.advice_column();
        let sibling = meta.advice_column();
        let sibling_index = meta.advice_column();
        let node = meta.advice_column();
        let index = meta.advice_column();
        let is_leaf = meta.advice_column();
        let parent = meta.advice_column();
        let parent_index = meta.advice_column();
        let aux_column = meta.advice_column();

        let config = PathChipConfig {
            depth,
            sibling,
            sibling_index,
            node,
            index,
            is_leaf,
            parent,
            parent_index,
            aux_column,
            sha256_table,
        };

        let columns = &[
            depth,
            sibling,
            sibling_index,
            node,
            index,
            is_leaf,
            parent,
            parent_index,
            aux_column,
        ];

        let mut height: usize = validators_num;
        let mut tree = vec![TreeLevel::new(meta, &config, height, PUBKEYS_LEVEL, 0)];

        for i in (1..TREE_DEPTH).rev() {
            let prev_height = height;
            height = validators_num * 2f64.powf((3 - TREE_DEPTH - i) as f64).ceil() as usize;
            let level = TreeLevel::new(meta, &config, height, i, prev_height);
            tree.push(level);
        }

        let mut tree: [_; TREE_DEPTH] = tree.into_iter().rev().collect_vec().try_into().unwrap();

        let mut pubkey_offset = 0;

        meta.lookup_any("public keys level", |meta| {
            let mut tree_level = &mut tree[PUBKEYS_LEVEL];

            let depth = tree_level.depth(meta);
            let node = tree_level.node(meta);
            let sibling = tree_level.sibling(meta);
            let mut constraint_builder: ConstraintBuilder<'_, F> =
                ConstraintBuilder::new(&mut tree_level.cell_manager);
            let s_level: Expression<F> =
                IsEqualGadget::construct(&mut constraint_builder, depth, PUBKEYS_LEVEL.expr())
                    .expr();

            let lookup_args = config.sha256_table.build_lookup(
                meta,
                s_level,
                node,
                sibling,
                tree[PUBKEYS_LEVEL - 1].parent_at(pubkey_offset * 3),
            );

            pubkey_offset += 1;

            lookup_args
        });

        config
    }
}
