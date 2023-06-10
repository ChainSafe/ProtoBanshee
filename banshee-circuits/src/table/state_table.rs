use crate::witness::{StateRow, StateEntry};

use super::*;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct StateTable {
    /// ValidatorIndex when tag == 'Validator', CommitteeIndex otherwise.
    pub id: Column<Advice>,
    /// Shuffle index
    pub order: Column<Advice>,
    /// Type of entity contained in BeaconState "god" object
    pub tag: Column<Advice>,
    /// Signals whether validator is active during that epoch.
    pub is_active: Column<Advice>,
    /// Signals whether validator have attested during that epoch.
    pub is_attested: Column<Advice>,
    /// Type of field the row represents.
    pub field_tag: Column<Advice>,
    /// Index for FieldTag
    pub index: Column<Advice>,
    /// Generalized index for State tree Merkle proofs.
    pub g_index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,

    // pub balance: Column<Advice>,
    // pub activation_epoch: Column<Advice>,
    // pub exit_epoch: Column<Advice>,
    // pub slashed: Column<Advice>,
    // pub pubkey_lo: Column<Advice>,
    // pub pubkey_hi: Column<Advice>,
}

impl<F: Field> LookupTable<F> for StateTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.id.into(),
            self.order.into(),
            self.tag.into(),
            self.is_active.into(),
            self.is_attested.into(),
            // self.balance.into(),
            // self.activation_epoch.into(),
            // self.exit_epoch.into(),
            // self.slashed.into(),
            // self.pubkey_lo.into(),
            // self.pubkey_hi.into(),
            self.field_tag.into(),
            self.index.into(),
            self.g_index.into(),
            self.value.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("id"),
            String::from("order"),
            String::from("tag"),
            String::from("is_active"),
            String::from("is_attested"),
            // String::from("balance"),
            // String::from("activation_epoch"),
            // String::from("exit_epoch"),
            // String::from("slashed"),
            // String::from("pubkey_lo"),
            // String::from("pubkey_hi"),
            String::from("field_tag"),
            String::from("index"),
            String::from("g_index"),
            String::from("value"),
        ]
    }
}

impl StateTable {
    /// Construct a new StateTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
            order: meta.advice_column(),
            tag: meta.advice_column(),
            is_active: meta.advice_column(),
            is_attested: meta.advice_column(),
            field_tag: meta.advice_column(),
            index: meta.advice_column(), // meta.advice_column_in(SecondPhase),
            g_index: meta.advice_column(), // meta.advice_column_in(SecondPhase),
            // balance: meta.advice_column(),
            // activation_epoch: meta.advice_column(),
            // exit_epoch: meta.advice_column(),
            // slashed: meta.advice_column(),
            // pubkey_lo: meta.advice_column(),
            // pubkey_hi: meta.advice_column(),
            value: meta.advice_column_in(SecondPhase),
        }
    }
    
    fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &StateRow<Value<F>>,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.id, row.id),
            (self.order, row.order),
            (self.tag, row.tag),
            (self.is_active, row.is_active),
            (self.is_attested, row.is_attested),
            // (self.balance, row.balance),
            // (self.activation_epoch, row.activation_epoch),
            // (self.exit_epoch, row.exit_epoch),
            // (self.slashed, row.slashed),
            // (self.pubkey_lo, row.pubkey_lo),
            // (self.pubkey_hi, row.pubkey_hi),
            (self.field_tag, row.field_tag),
            (self.index, row.index),
            (self.g_index, row.g_index),
            (self.value, row.value),
        ] {
            region.assign_advice(|| "assign state row on state table", column, offset, || value)?;
        }
        Ok(())
    }

    /// Load the state table into the circuit.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        entries: &[StateEntry],
        n_rows: usize,
        challenges: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "state table",
            |mut region| {
                for (offset, row) in entries.iter().flat_map(|e| e.table_assignment(challenges)).enumerate() {
                    self.assign(&mut region, offset, &row)?;
                };

                Ok(())
            },
        )
    }
}
