use std::vec;

use banshee_preprocessor::util::pad_to_ssz_chunk;
use eth_types::Field;
use gadgets::impl_expr;
use gadgets::util::rlc;
use halo2_base::utils::decompose_bigint_option;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::Expression;
use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Beacon validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: usize,
    pub is_active: bool,
    pub is_attested: bool,
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub slashed: bool,
    pub pubkey: Vec<u8>,
    pub gindex: u64,
}

/// Committee
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    pub id: usize,
    pub accumulated_balance: u64,
    pub aggregated_pubkey: Vec<u8>,
}

impl Validator {
    pub(crate) fn table_assignment<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<ValidatorsRow<Value<F>>> {
        let new_state_row =
            |field_tag: FieldTag, index: usize, value, ssz_rlc, gindex: u64| ValidatorsRow {
                id: Value::known(F::from(self.id as u64)),
                tag: Value::known(F::from(StateTag::Validator as u64)),
                is_active: Value::known(F::from(self.is_active as u64)),
                is_attested: Value::known(F::from(self.is_attested as u64)),
                field_tag: Value::known(F::from(field_tag as u64)),
                index: Value::known(F::from(index as u64)),
                gindex: Value::known(F::from(gindex)),
                value: Value::known(value),
                ssz_rlc,
            };

        let ssz_serialized = self.pubkey.to_vec();

        vec![
            new_state_row(
                FieldTag::EffectiveBalance,
                0,
                F::from(self.effective_balance as u64),
                randomness.map(|rnd| {
                    rlc::value(
                        &pad_to_ssz_chunk(&self.effective_balance.to_le_bytes()),
                        rnd,
                    )
                }),
                self.gindex * 2u64.pow(3) + 2, // 3 levels deeper, skip pubkeyRoot, withdrawalCredentials
            ),
            new_state_row(
                FieldTag::Slashed,
                0,
                F::from(self.slashed as u64),
                randomness.map(|rnd| rlc::value(&pad_to_ssz_chunk(&[self.slashed as u8]), rnd)),
                self.gindex * 2u64.pow(3) + 3,
            ),
            new_state_row(
                FieldTag::ActivationEpoch,
                0,
                F::from(self.activation_epoch as u64),
                randomness.map(|rnd| {
                    rlc::value(&pad_to_ssz_chunk(&self.activation_epoch.to_le_bytes()), rnd)
                }),
                self.gindex * 2u64.pow(3) + 5, // skip activationEligibilityEpoch
            ),
            new_state_row(
                FieldTag::ExitEpoch,
                0,
                F::from(self.exit_epoch as u64),
                randomness
                    .map(|rnd| rlc::value(&pad_to_ssz_chunk(&self.exit_epoch.to_le_bytes()), rnd)),
                self.gindex * 2u64.pow(3) + 6,
            ),
            new_state_row(
                FieldTag::PubKeyRLC,
                0,
                F::zero(),
                randomness.map(|rnd| rlc::value(&self.pubkey[0..32], rnd)),
                self.gindex * 2u64.pow(4), // pubkey chunks are 4 levels deeper
            ),
            new_state_row(
                FieldTag::PubKeyRLC,
                1,
                F::zero(),
                randomness.map(|rnd| rlc::value(&pad_to_ssz_chunk(&self.pubkey[32..48]), rnd)),
                self.gindex * 2u64.pow(4) + 1,
            ),
        ]
    }
}

impl Committee {
    pub(crate) fn table_assignment<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<ValidatorsRow<Value<F>>> {
        let new_state_row = |field_tag: FieldTag, index: usize, value| ValidatorsRow {
            id: Value::known(F::from(self.id as u64)),
            tag: Value::known(F::from(StateTag::Committee as u64)),
            is_active: Value::known(F::zero()),
            is_attested: Value::known(F::zero()),
            field_tag: Value::known(F::from(field_tag as u64)),
            index: Value::known(F::from(index as u64)),
            gindex: Value::known(F::zero()),
            value,
            ssz_rlc: Value::known(F::zero()),
        };

        let t = vec![new_state_row(
            FieldTag::EffectiveBalance,
            0,
            Value::known(F::from(self.accumulated_balance as u64)),
        )];

        vec![new_state_row(
            FieldTag::EffectiveBalance,
            0,
            Value::known(F::from(self.accumulated_balance as u64)),
        )]
        .into_iter()
        // .chain(decompose_bigint_option(Value::known(self.aggregated_pubkey.x), 7, 55).into_iter().map(|limb| new_state_row(FieldTag::PubKeyAffineX, 0, limb)))
        // .chain(decompose_bigint_option(Value::known(self.aggregated_pubkey.y), 7, 55).into_iter().map(|limb| new_state_row(FieldTag::PubKeyAffineX, 0, limb)))
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
pub enum StateTag {
    Validator = 0,
    Committee,
}
impl_expr!(StateTag);

impl From<StateTag> for usize {
    fn from(value: StateTag) -> usize {
        value as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTag {
    EffectiveBalance = 0,
    ActivationEpoch,
    ExitEpoch,
    Slashed,
    PubKeyRLC,
    PubKeyAffineX,
    PubKeyAffineY,
}
impl_expr!(FieldTag);

/// State table row assignment
#[derive(Clone, Copy, Debug)]
pub struct ValidatorsRow<F> {
    pub(crate) id: F,
    pub(crate) tag: F,
    pub(crate) is_active: F,
    pub(crate) is_attested: F,
    pub(crate) field_tag: F,
    pub(crate) index: F,
    pub(crate) gindex: F,
    pub(crate) value: F,
    pub(crate) ssz_rlc: F,
}

impl<F: Field> ValidatorsRow<F> {
    pub(crate) fn values(&self) -> [F; 9] {
        [
            self.id,
            self.tag,
            self.is_active,
            self.is_attested,
            self.field_tag,
            self.index,
            self.gindex,
            self.value,
            self.ssz_rlc,
        ]
    }

    pub(crate) fn rlc(&self, randomness: F) -> F {
        let values = self.values();
        values
            .iter()
            .rev()
            .fold(F::zero(), |acc, value| acc * randomness + value)
    }

    pub(crate) fn rlc_value(&self, randomness: Value<F>) -> Value<F> {
        randomness.map(|randomness| self.rlc(randomness))
    }
}
