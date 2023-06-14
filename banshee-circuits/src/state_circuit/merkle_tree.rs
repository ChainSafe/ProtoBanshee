use super::cell_manager::CellManager;
use crate::{
    state_circuit::{PathChipConfig, TREE_LEVEL_AUX_COLUMNS},
    util::{Cell, CellType},
    witness::LevelTag,
};
use eth_types::*;
use gadgets::{binary_number::BinaryNumberConfig, util::Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct TreeLevel<F> {
    depth: usize,
    config: PathChipConfig,
    pub(super) cell_manager: CellManager<F>,
}

impl<F: Field> TreeLevel<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        config: &PathChipConfig,
        height: usize,
        depth: usize,
        offset: usize,
    ) -> Self {
        let layout_column = &[
            config.depth,
            config.sibling,
            config.sibling_index,
            config.node,
            config.index,
            config.is_left,
            config.is_right,
            config.parent,
            config.parent_index,
            config.aux_column,
        ];
        let cell_manager =
            CellManager::new(meta, height, layout_column, &[config.aux_column], offset);

        Self {
            depth,
            config: config.clone(),
            cell_manager,
        }
    }

    pub fn tag_matches(&self, tag: LevelTag, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        let tag_bits = self
            .config
            .tag
            .bits
            .map(|bit| meta.query_advice(bit, Rotation::cur()));

        BinaryNumberConfig::<LevelTag, 2>::value_equals_expr(tag, tag_bits)
    }

    pub fn selector(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.config.selector, Rotation::cur())
    }

    pub fn depth(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.depth, Rotation::cur())
    }

    pub fn sibling(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.sibling, Rotation::cur())
    }

    pub fn sibling_index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.sibling_index, Rotation::cur())
    }

    pub fn node(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.node, Rotation::cur())
    }

    pub fn index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.index, Rotation::cur())
    }

    pub fn is_left(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.is_left, Rotation::cur())
    }

    pub fn is_right(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.is_right, Rotation::cur())
    }

    pub fn parent(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.parent, Rotation::cur())
    }

    pub fn parent_at(&self, row: usize) -> Expression<F> {
        self.cell_manager.query_exact(6, row).expr()
    }

    pub fn parent_index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.config.parent_index, Rotation::cur())
    }
}
