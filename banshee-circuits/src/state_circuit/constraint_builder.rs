use super::{cell_manager::*};
use crate::{util::{Expr, Cell, CellType, Constraint, Lookup, ConstrainBuilderCommon}, state_circuit::*};
use eth_types::Field;
use halo2_proofs::plonk::Expression;

pub struct ConstraintBuilder<F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    condition: Expression<F>,
    pub(crate) cell_manager: CellManager<F>,
}

impl<F: Field> ConstraintBuilder<F> {
    pub fn new(cell_manager: CellManager<F>) -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            condition: 1.expr(),
            cell_manager,
        }
    }
}

impl<F: Field> ConstrainBuilderCommon<F> for ConstraintBuilder<F> {
    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.constraints.push((name, self.condition.clone() * constraint));
    }
    
    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        self.cell_manager.query_cells(cell_type, count)
    }
}

// #[derive(Clone)]
// pub struct Queries<F: Field> {
//     depth: Expression<F>,
//     sibling: Expression<F>,
//     sibling_index: Expression<F>,
//     node: Expression<F>,
//     index: Expression<F>,
//     is_leaf: Expression<F>,
//     // is_left: Column<Advice>,
//     parent: Expression<F>,
//     parent_index: Column<Advice>,
// }
