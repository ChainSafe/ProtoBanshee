use itertools::Itertools;

use crate::witness::{into_casper_entities, CasperEntityRow, Committee, Validator};

use super::*;

/// The StateTable contains records of the state of the beacon chain.
#[derive(Clone, Debug)]
pub struct ValidatorsTable {
    /// ValidatorIndex when tag == 'Validator', CommitteeIndex otherwise.
    pub id: Column<Advice>,
    /// Validator or Committee
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
    pub gindex: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// SSZ chunk RLC
    pub ssz_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for ValidatorsTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.id.into(),
            self.tag.into(),
            self.is_active.into(),
            self.is_attested.into(),
            self.field_tag.into(),
            self.index.into(),
            self.gindex.into(),
            self.value.into(),
            self.ssz_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("id"),
            String::from("tag"),
            String::from("is_active"),
            String::from("is_attested"),
            String::from("field_tag"),
            String::from("index"),
            String::from("gindex"),
            String::from("value"),
            String::from("ssz_rlc"),
        ]
    }
}

impl ValidatorsTable {
    /// Construct a new [`ValidatorsTable`]
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column(),
            tag: meta.advice_column(),
            is_active: meta.advice_column(),
            is_attested: meta.advice_column(),
            field_tag: meta.advice_column(),
            index: meta.advice_column(), // meta.advice_column_in(SecondPhase),
            gindex: meta.advice_column_in(SecondPhase),
            value: meta.advice_column_in(SecondPhase),
            ssz_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    pub fn assign_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &CasperEntityRow<Value<F>>,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.id, row.id),
            (self.tag, row.tag),
            (self.is_active, row.is_active),
            (self.is_attested, row.is_attested),
            (self.field_tag, row.field_tag),
            (self.index, row.index),
            (self.gindex, row.gindex),
            (self.value, row.value),
            (self.ssz_rlc, row.ssz_rlc),
        ] {
            region.assign_advice(
                || "assign state row on state table",
                column,
                offset,
                || value,
            )?;
        }
        Ok(())
    }

    /// Load the validators table into the circuit.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        validators: &[Validator],
        committees: &[Committee],
        challenge: Value<F>,
    ) -> Result<(), Error> {
        let casper_entities = into_casper_entities(validators.iter(), committees.iter());

        layouter.assign_region(
            || "dev load state table",
            |mut region| {
                self.annotate_columns_in_region(&mut region);
                for (offset, row) in casper_entities
                    .iter()
                    .flat_map(|e| e.table_assignment(challenge))
                    .enumerate()
                {
                    self.assign_with_region(&mut region, offset, &row)?;
                }

                Ok(())
            },
        )
    }

    pub fn build_lookup<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        enable: Expression<F>,
        gindex: Expression<F>,
        value_rlc: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        vec![
            (
                gindex.clone() * enable.clone(),
                meta.query_advice(self.gindex, Rotation::cur()),
            ),
            (
                value_rlc.clone() * enable.clone(),
                meta.query_advice(self.ssz_rlc, Rotation::cur()),
            ), // TODO: should any other columns be included?
        ]
    }
}
