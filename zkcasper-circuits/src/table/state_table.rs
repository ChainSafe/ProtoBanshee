use gadgets::util::rlc;

use std::collections::HashMap;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{
    state_circuit::{PUBKEYS_LEVEL, VALIDATORS_LEVEL},
    witness::{MerkleTrace, MerkleTraceStep},
};

use super::*;

#[derive(Clone, Debug)]
pub struct StateTables(HashMap<StateTreeLevel, StateTable>);

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct StateTable {
    pub is_enabled: Column<Fixed>,
    pub sibling: Column<Advice>,
    pub sibling_index: Column<Advice>,
    pub node: Column<Advice>,
    pub index: Column<Advice>,
}

#[derive(Clone, Debug, EnumIter, PartialEq, Eq, Hash)]
pub enum StateTreeLevel {
    PubKeys,
    Validators,
}

impl<F: Field> LookupTable<F> for StateTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.sibling.into(),
            self.sibling_index.into(),
            self.node.into(),
            self.index.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("sibling"),
            String::from("sibling_index"),
            String::from("node"),
            String::from("index"),
        ]
    }
}

impl StateTable {
    // For `StateTables::dev_constract` only.
    fn constuct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let is_enabled = meta.fixed_column();
        let sibling = meta.advice_column();
        let sibling_index = meta.advice_column_in(FirstPhase);
        let node = meta.advice_column();
        let index = meta.advice_column_in(FirstPhase);

        Self {
            is_enabled,
            sibling,
            sibling_index,
            node,
            index,
        }
    }

    // For `StateTables::dev_constract` only. Must not be used in `StateCircuit` as it does not adds padding.
    fn assign_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        steps: Vec<&MerkleTraceStep>,
        challange: Value<F>,
    ) -> Result<(), Error> {
        for (i, step) in steps.into_iter().enumerate() {
            assert_eq!(step.sibling.len(), 32);
            assert_eq!(step.node.len(), 32);
            let node_rlc = challange.map(|rnd| rlc::value(&step.node, rnd));
            let sibling_rlc = challange.map(|rnd| rlc::value(&step.sibling, rnd));

            region.assign_fixed(
                || "is_enabled",
                self.is_enabled,
                i,
                || Value::known(F::one()),
            )?;
            region.assign_advice(|| "sibling", self.sibling, i, || sibling_rlc)?;
            region.assign_advice(
                || "sibling_index",
                self.sibling_index,
                i,
                || Value::known(F::from(step.sibling_index)),
            )?;
            region.assign_advice(|| "node", self.node, i, || node_rlc)?;
            region.assign_advice(
                || "index",
                self.index,
                i,
                || Value::known(F::from(step.index)),
            )?;
        }

        Ok(())
    }
}

impl StateTables {
    /// Construct a new [`ValidatorsTable`] outside of [`StateTable`].
    pub fn dev_construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        StateTables(
            StateTreeLevel::iter()
                .map(|level| (level, StateTable::constuct(meta)))
                .collect(),
        )
    }

    /// Load state tables without running the full [`StateTable`].
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        trace: &MerkleTrace,
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let mut trace_by_depth = trace.trace_by_level_map();

        let pubkey_level_trace = trace_by_depth.remove(&PUBKEYS_LEVEL).unwrap();
        let validators_level_trace = trace_by_depth.remove(&VALIDATORS_LEVEL).unwrap();

        let pubkey_table = self.0.get(&StateTreeLevel::PubKeys).unwrap();
        let validators_table = self.0.get(&StateTreeLevel::Validators).unwrap();

        layouter.assign_region(
            || "dev load state tables",
            |mut region| {
                pubkey_table.annotate_columns_in_region(&mut region);
                validators_table.annotate_columns_in_region(&mut region);

                pubkey_table.assign_with_region(
                    &mut region,
                    pubkey_level_trace.clone(),
                    challenge,
                )?;
                validators_table.assign_with_region(
                    &mut region,
                    validators_level_trace.clone(),
                    challenge,
                )?;

                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        level: StateTreeLevel,
        is_left: bool,
        enable: Expression<F>,
        gindex: Expression<F>,
        value_rlc: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let lookup_table = self.0.get(&level).unwrap();
        let value_col = if is_left {
            lookup_table.node
        } else {
            lookup_table.sibling
        };
        let index_col = if is_left {
            lookup_table.index
        } else {
            lookup_table.sibling_index
        };

        vec![
            (
                enable.clone(),
                meta.query_fixed(lookup_table.is_enabled, Rotation::cur()),
            ),
            (
                value_rlc * enable.clone(),
                meta.query_advice(value_col, Rotation::cur()),
            ),
            (
                gindex * enable,
                meta.query_advice(index_col, Rotation::cur()),
            ),
        ]
    }
}
