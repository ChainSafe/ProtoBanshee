use super::cell_manager::*;
use crate::{
    gadget::LtGadget,
    table::state_table::StateTables,
    util::{Cell, CellType, ConstrainBuilderCommon, Constraint, Expr, Lookup},
    witness::{CasperEntity, CasperEntityRow, Committee, StateTag, Validator},
    N_BYTES_U64,
};
use eth_types::Field;
use gadgets::{binary_number::BinaryNumberConfig, util::not};
use halo2_proofs::{circuit::Region, plonk::Expression};
use strum::IntoEnumIterator;

pub struct ConstraintBuilder<'a, F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    pub max_degree: usize,
    condition: Expression<F>,
    pub(crate) cell_manager: &'a mut CellManager<F>,
}

impl<'a, F: Field> ConstraintBuilder<'a, F> {
    pub fn new(cell_manager: &'a mut CellManager<F>, max_degree: usize) -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            max_degree,
            condition: 1.expr(),
            cell_manager,
        }
    }

    pub fn gate(&self, condition: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .iter()
            .cloned()
            .map(|(name, expression)| (name, condition.clone() * expression))
            .collect()
    }

    pub fn lookups(&self) -> Vec<Lookup<F>> {
        self.lookups.clone()
    }

    fn add_lookup(&mut self, name: &'static str, lookup: Vec<(Expression<F>, Expression<F>)>) {
        let mut lookup = lookup;
        for (expression, _) in lookup.iter_mut() {
            *expression = expression.clone() * self.condition.clone();
        }
        self.lookups.push((name, lookup));
    }

    pub(crate) fn validate_degree(&self, degree: usize, name: &'static str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high: {} > {}",
                name,
                degree,
                self.max_degree,
            );
        }
    }
}

impl<'a, F: Field> ConstrainBuilderCommon<F> for ConstraintBuilder<'a, F> {
    fn condition<R>(&mut self, condition: Expression<F>, build: impl FnOnce(&mut Self) -> R) -> R {
        let original_condition = self.condition.clone();
        self.condition = self.condition.clone() * condition;
        let res = build(self);
        self.condition = original_condition;
        res
    }

    fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.validate_degree(constraint.degree(), name);
        self.constraints
            .push((name, self.condition.clone() * constraint));
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        self.cell_manager.query_cells(cell_type, count)
    }
}

#[derive(Clone)]
pub struct Queries<F: Field> {
    pub q_enabled: Expression<F>,
    pub target_epoch: Expression<F>,
    pub state_table: StateQueries<F>,
    // pub tag_bits: [Expression<F>; 3],
}

#[derive(Clone)]
pub struct StateQueries<F: Field> {
    pub id: Expression<F>,
    pub order: Expression<F>,
    pub tag: Expression<F>,
    pub is_active: Expression<F>,
    pub is_attested: Expression<F>,
    pub balance: Expression<F>,
    pub activation_epoch: Expression<F>,
    pub exit_epoch: Expression<F>,
    pub slashed: Expression<F>,
    pub pubkey_lo: Expression<F>,
    pub pubkey_hi: Expression<F>,
    pub field_tag: Expression<F>,
    pub index: Expression<F>,
    pub g_index: Expression<F>,
    pub value: Expression<F>,
}

impl<F: Field> Queries<F> {
    pub fn selector(&self) -> Expression<F> {
        self.q_enabled.clone()
    }

    pub fn is_validator(&self) -> Expression<F> {
        self.state_table.tag.clone()
    }

    pub fn is_committee(&self) -> Expression<F> {
        not::expr(self.state_table.tag.clone())
    }
    
    pub fn target_epoch(&self) -> Expression<F> {
        self.target_epoch.clone()
    }

    pub fn next_epoch(&self) -> Expression<F> {
        self.target_epoch.clone() + 1.expr()
    }

    pub fn id(&self) -> Expression<F> {
        self.state_table.id.clone()
    }

    pub fn tag(&self) -> Expression<F> {
        self.state_table.tag.clone()
    }

    pub fn is_active(&self) -> Expression<F> {
        self.state_table.is_active.clone()
    }

    pub fn is_attested(&self) -> Expression<F> {
        self.state_table.is_attested.clone()
    }

    pub fn balance(&self) -> Expression<F> {
        self.state_table.balance.clone()
    }

    pub fn activation_epoch(&self) -> Expression<F> {
        self.state_table.activation_epoch.clone()
    }

    pub fn exit_epoch(&self) -> Expression<F> {
        self.state_table.exit_epoch.clone()
    }

    pub fn slashed(&self) -> Expression<F> {
        self.state_table.slashed.clone()
    }

    pub fn pubkey_lo(&self) -> Expression<F> {
        self.state_table.pubkey_lo.clone()
    }

    pub fn pubkey_hi(&self) -> Expression<F> {
        self.state_table.pubkey_hi.clone()
    }
}
