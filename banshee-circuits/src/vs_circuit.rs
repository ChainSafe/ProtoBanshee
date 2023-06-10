mod constraint_builder;

use constraint_builder::*;

use crate::{
    table::{LookupTable, StateTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, StateEntry, StateTag},
};
// use constraint_builder::{ConstraintBuilder, Queries};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
// use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};

#[derive(Clone)]
pub struct ValidatorsCircuitConfig {
    selector: Column<Fixed>,
    state_table: StateTable,
    tag: BinaryNumberConfig<StateTag, 3>,
}

impl<F: Field> SubCircuitConfig<F> for ValidatorsCircuitConfig {
    type ConfigArgs = StateTable;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let selector = meta.fixed_column();
        let state_table = args;


        meta.create_gate("verify activated validators", |meta:| {
            
        })

        Self { selector, state_table }
    }
}


fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &ValidatorsCircuitConfig) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.selector, Rotation::cur()),
        state_table: StateQueries {
            id: meta.query_advice(c.state_table.id, Rotation::cur()),
            order: meta.query_advice(c.state_table.id, Rotation::cur()),
            tag: meta.query_advice(c.state_table.tag, Rotation::cur()),
            is_active: meta.query_advice(c.state_table.is_active, Rotation::cur()),
            is_attested: meta.query_advice(c.state_table.is_attested, Rotation::cur()),
            // field_tag: meta.query_advice(c.state_table.field_tag, Rotation::cur()),
            index: meta.query_advice(c.state_table.index, Rotation::cur()),
            value: meta.query_advice(c.state_table.value, Rotation::cur()),
            value_prev: meta.query_advice(c.state_table.value, Rotation::prev()),
        },
        tag_bits: c
            .tag
            .bits
            .map(|bit| meta.query_advice(bit, Rotation::cur())),
    }

}
