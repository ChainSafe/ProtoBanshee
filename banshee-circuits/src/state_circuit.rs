use crate::{util::ConstrainBuilderCommon, witness::LevelTag, MAX_VALIDATORS};

pub mod cell_manager;
use cell_manager::CellManager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use merkle_tree::TreeLevel;
use rand_chacha::rand_core::le;

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
    util::{not, Expr},
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
use std::{
    fmt::format,
    iter,
    ops::{Add, Mul},
    vec,
};

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
// pub const TREE_MAX_LEAVES: usize = MAX_VALIDATORS * CHUNKS_PER_VALIDATOR;
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;
pub const VALIDATORS_LEVEL: usize = PUBKEYS_LEVEL - 1;

#[derive(Clone, Debug)]
pub(crate) struct PathChipConfig<F: Field> {
    selector: Column<Fixed>,
    tree: [TreeLevel<F>; TREE_DEPTH],
    aux_column: Column<Advice>,
    sha256_table: SHA256Table,
}

/// chip for verify Merkle-multi proof
pub(crate) struct PathChip<'a, F: Field> {
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
        validators_num: usize,
    ) -> <Self as Chip<F>>::Config {
        let selector = meta.fixed_column();
        let aux_column = meta.advice_column();

        let mut height: usize = validators_num;
        let mut tree = vec![TreeLevel::configure(
            meta,
            height,
            PUBKEYS_LEVEL,
            0,
            3,
            true,
        )];

        let padding = 0;
        for i in (1..TREE_DEPTH).rev() {
            let prev_height = height;
            height = validators_num * 2f64.powf((3 - TREE_DEPTH - i) as f64).ceil() as usize;
            if i != VALIDATORS_LEVEL {
                padding = padding * 2 + 1;
            }
            let level =
                TreeLevel::configure(meta, height, i, prev_height, padding, i == VALIDATORS_LEVEL);
            tree.push(level);
        }

        let mut tree: [_; TREE_DEPTH] = tree.into_iter().rev().collect_vec().try_into().unwrap();

        for i in (0..TREE_DEPTH).rev() {
            let level = tree[i];
            let next_level = tree[i - 1];

            meta.create_gate(format!("tree[{i}] boolean checks"), |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cb = ConstraintBuilder::new();
                cb.require_boolean("into_left is boolean", level.into_left(meta));
                if let Some(is_left_col) = level.is_left {
                    cb.require_boolean(
                        "is_left is boolean",
                        meta.query_advice(is_left_col, Rotation::cur()),
                    );
                }
                if let Some(is_right_col) = level.is_right {
                    cb.require_boolean(
                        "is_right is boolean",
                        meta.query_advice(is_right_col, Rotation::cur()),
                    );
                }
                cb.gate(selector)
            });

            if let Some(is_left_col) = level.is_left {
                meta.lookup_any(
                    format!("state_table.lookup(tree[{i}][node], tree[{i}][index])"),
                    |meta| {
                        let selector = meta.query_fixed(selector, Rotation::cur());
                        let is_left = meta.query_advice(is_left_col, Rotation::cur());

                        // TODO: constraint (node, index) with StateTable
                        // https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/zkevm-circuits/src/evm_circuit/execution.rs#L815-L816
                        // state_table.build_lookup(
                        //     meta,
                        //     selector * is_left,
                        //     level.node(meta),
                        //     level.node_index(meta),
                        // )
                        vec![]
                    },
                );
            }

            if let Some(is_right_col) = level.is_right {
                meta.lookup_any(
                    format!("state_table.lookup(tree[{i}][sibling], tree[{i}][sibling_index])"),
                    |meta| {
                        let selector = meta.query_fixed(selector, Rotation::cur());
                        let is_right = meta.query_advice(is_right_col, Rotation::cur());

                        // TODO: constraint (sibling, sibling_index) with StateTable
                        // state_table.build_lookup(
                        //     meta,
                        //     selector * is_right,
                        //     level.sibling(meta),
                        //     level.sibling_index(meta),
                        // )
                        vec![]
                    },
                );
            }

            meta.lookup_any(
                format!(
                    "hash(tree[{i}][node] | tree[{i}][sibling]) == tree[{}][node]",
                    i - 1
                ),
                |meta| {
                    let selector = meta.query_fixed(selector, Rotation::cur());
                    let into_node = level.into_left(meta);
                    sha256_table.build_lookup(
                        meta,
                        selector * into_node,
                        level.node(meta),
                        level.sibling(meta),
                        next_level.node(meta),
                    )
                },
            );

            meta.lookup_any(format!("hash(tree[{i}][node] | tree[{i}][sibling]) == tree[{}][sibling]@rotation(-(padding + 1))", i-1), |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let into_sibling: Expression<F> = not::expr(level.into_left(meta));
                sha256_table.build_lookup(
                    meta,
                    selector * into_sibling,
                    level.node(meta),
                    level.sibling(meta),
                    next_level.sibling_at(level.padding().add(1).mul(-1), meta),
                )
            });
        }

        PathChipConfig {
            selector,
            tree,
            aux_column,
            sha256_table,
        }
    }
}
