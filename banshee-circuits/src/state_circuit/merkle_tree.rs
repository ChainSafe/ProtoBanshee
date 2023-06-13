use super::cell_manager::{Cell,CellManager, CellType};
use crate::casper_circuit::TREE_LEVEL_COLUMNS;
use eth_types::*;
use halo2_proofs::{
    circuit::Value,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
};


#[derive(Clone, Debug)]
pub struct TreeLevel<F, const MAX_LEAVES: usize> {
    depth: usize,
    cell_manager: CellManager<F>,
}

impl<F: Field, const MAX_LEAVES: usize> TreeLevel<F, MAX_LEAVES> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        hight: Option<usize>,
        advices: [Column<Advice>; TREE_LEVEL_COLUMNS],
        depth: usize,
        offset: usize,
    ) -> Self {
        let height = hight.unwrap_or(MAX_LEAVES / 2 * depth);
        let mut cell_manager = CellManager::new(meta, height, &advices, offset);
        
        Self {
            depth,
            cell_manager,
        }
    }

}
