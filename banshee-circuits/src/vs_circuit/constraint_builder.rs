use crate::{util::Expr, witness::StateTag};
use eth_types::Field;
use gadgets::binary_number::BinaryNumberConfig;
use halo2_proofs::plonk::Expression;
use strum::IntoEnumIterator;

type Constraint<F> = (&'static str, Expression<F>);
type Lookup<F> = (&'static str, Vec<(Expression<F>, Expression<F>)>);

pub struct ConstraintBuilder<F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    condition: Expression<F>,
}

impl<F: Field> ConstraintBuilder<F> {
    pub fn new() -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            condition: 1.expr(),
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

    pub fn build(&mut self, q: &Queries<F>) {
        self.build_general_constraints(q);
        self.condition(q.tag_matches(StateTag::Validator), |cb| {
            cb.build_validator_constraints(q)
        });
       
    }

    fn build_general_constraints(&mut self, q: &Queries<F>) {
        self.require_boolean("is_active is boolean", q.is_active());
        self.require_boolean("is_attested is boolean", q.is_attested());

        self.condition(q.is_attested(), |cb| {
            cb.require_equal(
                "is_active is true when is_attested is true",
                q.is_active(),
                1.expr(),
            );
        });
        // tag value in StateTable range is enforced in BinaryNumberChip
    }

    fn build_validator_constraints(&mut self, q: &Queries<F>) {
       self.require_boolean("slashed is boolean", q.slashed());

       self.condition(q.is_active(), |cb| {
           cb.require_boolean("slashed is false for active validators", q.slashed());


       });
    }

    fn require_zero(&mut self, name: &'static str, e: Expression<F>) {
        self.constraints.push((name, self.condition.clone() * e));
    }

    fn require_equal(&mut self, name: &'static str, left: Expression<F>, right: Expression<F>) {
        self.require_zero(name, left - right)
    }

    fn require_boolean(&mut self, name: &'static str, e: Expression<F>) {
        self.require_zero(name, e.clone() * (1.expr() - e))
    }

    fn require_in_set(&mut self, name: &'static str, item: Expression<F>, set: Vec<Expression<F>>) {
        self.require_zero(
            name,
            set.iter().fold(1.expr(), |acc, element| {
                acc * (item.clone() - element.clone())
            }),
        );
    }

    fn add_lookup(&mut self, name: &'static str, lookup: Vec<(Expression<F>, Expression<F>)>) {
        let mut lookup = lookup;
        for (expression, _) in lookup.iter_mut() {
            *expression = expression.clone() * self.condition.clone();
        }
        self.lookups.push((name, lookup));
    }

    fn condition(&mut self, condition: Expression<F>, build: impl FnOnce(&mut Self)) {
        let original_condition = self.condition.clone();
        self.condition = self.condition.clone() * condition;
        build(self);
        self.condition = original_condition;
    }
}


#[derive(Clone)]
pub struct Queries<F: Field> {
    pub selector: Expression<F>,
    pub state_table: StateQueries<F>,
    pub tag_bits: [Expression<F>; 3],
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
    //pub field_tag: Expression<F>,
    pub index: Expression<F>,
    pub value: Expression<F>,
    pub value_prev: Expression<F>,
}

impl<F: Field> Queries<F> {
    fn selector(&self) -> Expression<F> {
        self.selector.clone()
    }

    fn id(&self) -> Expression<F> {
        self.state_table.id.clone()
    }

    fn tag(&self) -> Expression<F> {
        self.state_table.tag.clone()
    }

    fn is_active(&self) -> Expression<F> {
        self.state_table.is_active.clone()
    }

    fn is_attested(&self) -> Expression<F> {
        self.state_table.is_attested.clone()
    }

    fn balance(&self) -> Expression<F> {
        self.state_table.balance.clone()
    }

    fn activation_epoch(&self) -> Expression<F> {
        self.state_table.activation_epoch.clone()
    }

    fn exit_epoch(&self) -> Expression<F> {
        self.state_table.exit_epoch.clone()
    }

    fn slashed(&self) -> Expression<F> {
        self.state_table.slashed.clone()
    }

    fn pubkey_lo(&self) -> Expression<F> {
        self.state_table.pubkey_lo.clone()
    }

    fn pubkey_hi(&self) -> Expression<F> {
        self.state_table.pubkey_hi.clone()
    }

    fn value(&self) -> Expression<F> {
        self.state_table.value.clone()
    }

    fn value_prev(&self) -> Expression<F> {
        self.state_table.value_prev.clone()
    }
   
    fn tag_matches(&self, tag: StateTag) -> Expression<F> {
        BinaryNumberConfig::<StateTag, 3>::value_equals_expr(tag, self.tag_bits.clone())
    }
}
