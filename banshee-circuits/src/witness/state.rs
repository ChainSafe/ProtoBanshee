use eth_types::Field;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};
use itertools::Itertools;

/// Beacon state entry. State entries are used for connecting CasperCircuit and
/// AttestationsCircuit.
#[derive(Clone, Copy, Debug)]
pub enum StateEntry {
    /// Validator
    Validator {
        id: usize,
        order: usize,
        committee: usize,
        is_active: bool,
        is_attested: bool,
        effective_balance: u64,
        activation_epoch: u64,
        exit_epoch: u64,
        slashed: bool,
        pubkey: [u8; 48],
    },
    /// Committee
    Committee {
        id: usize,
        accumulated_balance: u64,
        aggregated_pubkey: G1Affine,
    },
}

impl StateEntry {
    pub(crate) fn table_assignment<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<StateRow<Value<F>>> {
        match self {
            StateEntry::Validator {
                id,
                order,
                committee,
                is_active,
                is_attested,
                effective_balance,
                activation_epoch,
                exit_epoch,
                slashed,
                pubkey,
            } => {
                let new_state_row = |field_tag, index, value| StateRow {
                    id: Value::known(F::from(*id as u64)),
                    order: Value::known(F::from(*order as u64)),
                    tag: Value::known(F::from(StateTag::Validator as u64)),
                    is_active: Value::known(F::from(*is_active as u64)),
                    is_attested: Value::known(F::from(*is_attested as u64)),
                    field_tag: Value::known(F::from(field_tag as u64)),
                    index: Value::known(F::from(index as u64)),
                    value,
                };

                vec![
                    new_state_row(
                        FieldTag::EffectiveBalance,
                        0,
                        Value::known(F::from(*effective_balance as u64)),
                    ),
                    new_state_row(
                        FieldTag::ActivationEpoch,
                        0,
                        Value::known(F::from(*activation_epoch as u64)),
                    ),
                    new_state_row(
                        FieldTag::ExitEpoch,
                        0,
                        Value::known(F::from(*exit_epoch as u64)),
                    ),
                    new_state_row(
                        FieldTag::Slashed,
                        0,
                        Value::known(F::from(*slashed as u64)),
                    ),
                    new_state_row(
                        FieldTag::PubKeyCompressed,
                        0,
                        Value::known(F::from_bytes(pubkey)),
                    ),
                    new_state_row(
                        FieldTag::PubKeyCompressed,
                        0,
                        Value::known(F::from_bytes(pubkey)),
                    ),
                ]
            }
            StateEntry::Committee {
                id,
                accumulated_balance,
                aggregated_pubkey,
            } => todo!(),
        }
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateTag {
    Validator = 0,
    Committee,
}
impl_expr!(StateTag);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTag {
    EffectiveBalance = 0,
    ActivationEpoch,
    ExitEpoch,
    Slashed,
    PubKeyCompressed,
    PubKeyAffineX,
    PubKeyAffineY,
}
impl_expr!(FieldTag);


/// State table row assignment
#[derive(Default, Clone, Copy, Debug)]
pub struct StateRow<F> {
    pub(crate) id: F,
    pub(crate) order: F,
    pub(crate) tag: F,
    pub(crate) is_active: F,
    pub(crate) is_attested: F,
    pub(crate) field_tag: F,
    pub(crate) index: F,
    pub(crate) value: F,
}

impl<F: Field> StateRow<F> {
    pub(crate) fn values(&self) -> [F; 8] {
        [
            self.id,
            self.order,
            self.tag,
            self.is_active,
            self.is_attested,
            self.field_tag,
            self.index,
            self.value,
        ]
    }
    pub(crate) fn rlc(&self, randomness: F) -> F {
        let values = self.values();
        values
            .iter()
            .rev()
            .fold(F::ZERO, |acc, value| acc * randomness + value)
    }

    pub(crate) fn rlc_value(&self, randomness: Value<F>) -> Value<F> {
        randomness.map(|randomness| self.rlc(randomness))
    }
}
