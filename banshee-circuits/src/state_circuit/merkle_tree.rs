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
use rand_chacha::rand_core::le;

#[derive(Clone, Debug)]
pub struct TreeLevel<F> {
    depth: usize,
    padding: usize,
    sibling: Column<Advice>,
    sibling_index: Column<Advice>,
    node: Column<Advice>,
    index: Column<Advice>,
    into_left: Column<Advice>,
    pub(crate) is_left:  Option<Column<Advice>>,
    pub(crate) is_right: Option<Column<Advice>>,
    _f: std::marker::PhantomData<F>,
   // pub(super) cell_manager: CellManager<F>,
}

impl<F: Field> TreeLevel<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        height: usize,
        depth: usize,
        offset: usize,
        padding: usize,
        has_leaves: bool,
    ) -> Self {
        let sibling = meta.advice_column();
        let sibling_index = meta.advice_column();
        let node = meta.advice_column();
        let index = meta.advice_column();
        let into_left = meta.advice_column();
        let is_left = if has_leaves {
            Some(meta.advice_column())
        } else {
            None
        };
        let is_right = if has_leaves {
            Some(meta.advice_column())
        } else {
            None
        };
        // let cell_manager =
        //     CellManager::new(meta, height, layout_column, &[config.aux_column], offset);

        Self {
            depth,
            padding,
            sibling,
            sibling_index,
            node,
            index,
            into_left,
            is_left,
            is_right,
            _f: std::marker::PhantomData,
        }
    }

    pub fn padding(&self) -> i32 {
        self.padding as i32
    }

    pub fn sibling(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation::cur())
    }

    pub fn sibling_next(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation(self.padding() + 1))
    }

    pub fn sibling_at(&self, offset: i32, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling, Rotation(offset))
    }

    pub fn sibling_index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.sibling_index, Rotation::cur())
    }

    pub fn node(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation::cur())
    }

    pub fn node_next(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation(self.padding() + 1))
    }

    pub fn node_at(&self, offset: i32, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.node, Rotation(offset))
    }

    pub fn index(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.index, Rotation::cur())
    }

    pub fn into_left(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_advice(self.into_left, Rotation::cur())
    }
}
