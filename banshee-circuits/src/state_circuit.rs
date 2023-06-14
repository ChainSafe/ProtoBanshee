use crate::{MAX_VALIDATORS, witness::LevelTag};

pub mod cell_manager;
use cell_manager::CellManager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use merkle_tree::TreeLevel;
use serde::__private::de;

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
use std::{iter, vec};

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
// pub const TREE_MAX_LEAVES: usize = MAX_VALIDATORS * CHUNKS_PER_VALIDATOR;
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;
pub const VALIDATOR_FIELDS_LEVEL: usize = PUBKEYS_LEVEL - 1;

#[derive(Clone, Debug)]
pub (crate) struct PathChipConfig {
    selector: Column<Fixed>,
    depth: Column<Advice>,
    sibling: Column<Advice>,
    sibling_index: Column<Advice>,
    node: Column<Advice>,
    index: Column<Advice>,
    is_left: Column<Advice>,
    is_right: Column<Advice>,
    parent: Column<Advice>,
    parent_index: Column<Advice>,
    tag: BinaryNumberConfig<LevelTag, 2>,
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
        let selector = meta.fixed_column();
        let depth = meta.advice_column();
        let sibling = meta.advice_column();
        let sibling_index = meta.advice_column();
        let node = meta.advice_column();
        let index = meta.advice_column();
        let is_left = meta.advice_column();
        let is_right = meta.advice_column();
        let parent = meta.advice_column();
        let parent_index = meta.advice_column();
        let aux_column = meta.advice_column();
        let tag = BinaryNumberChip::configure(meta, selector, None);

        let config = PathChipConfig {
            selector,
            depth,
            sibling,
            sibling_index,
            node,
            index,
            is_left,
            is_right,
            parent,
            parent_index,
            tag,
            aux_column,
            sha256_table,
        };

        let mut height: usize = validators_num;
        let mut tree = vec![TreeLevel::new(meta, &config, height, PUBKEYS_LEVEL, 0)];

        for i in (1..TREE_DEPTH).rev() {
            let prev_height = height;
            height = validators_num * 2f64.powf((3 - TREE_DEPTH - i) as f64).ceil() as usize;
            let level = TreeLevel::new(meta, &config, height, i, prev_height);
            tree.push(level);
        }

        let mut tree: [_; TREE_DEPTH] = tree.into_iter().rev().collect_vec().try_into().unwrap();

        meta.lookup_any("validator fields in state table", |meta| {
            let node = meta.query_advice(config.node, Rotation::cur());
            let index = meta.query_advice(config.index, Rotation::cur());
            let sibling = meta.query_advice(config.sibling, Rotation::cur());
            let sibling_index = meta.query_advice(config.sibling_index, Rotation::cur());

            // TODO: constraint (node, index) and (sibling, s_index) with StateTable
            // https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/zkevm-circuits/src/evm_circuit/execution.rs#L815-L816
            vec![]
        });

        meta.lookup_any("hash(node + sibling) == parent", |meta| {
            let mut tree_level = &mut tree[PUBKEYS_LEVEL];


            let depth = tree_level.depth(meta);
            let node = tree_level.node(meta);
            let sibling = tree_level.sibling(meta);
            
            config.sha256_table.build_lookup(
                meta,
                tree_level.selector(meta),
                tree_level.node(meta),
                tree_level.sibling(meta),
                tree_level.parent(meta), // tree[PUBKEYS_LEVEL - 1].parent_at(pubkey_offset * 3),
            )
        });

        // let s_level: Expression<F> = tree_level.tag_matches(LevelTag::PubKeys, meta);


        meta.lookup_any("middle levels", |meta| {
            let mut tree_level = &mut tree[PUBKEYS_LEVEL];

            let depth = tree_level.depth(meta);
            let node = tree_level.node(meta);
            let sibling = tree_level.sibling(meta);
            let s_level = tree_level.tag_matches(LevelTag::Validators, meta);
            let s_left = tree_level.is_left(meta);
            let s_right = tree_level.is_right(meta);

            let lookup_args = config.sha256_table.build_lookup(
                meta,
                s_level * s_left,
                node,
                sibling,
                tree[PUBKEYS_LEVEL - 1].parent_at(pubkey_offset * 3),
            );

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
