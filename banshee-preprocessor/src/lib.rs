use ethereum_consensus::primitives::BlsPublicKey;
use merkle_proof::*;
use ethereum_types::H256;
use ssz_rs::prelude::*;

#[derive(Default, Debug, SimpleSerialize, Clone)]
struct SimpleValidator {
    balance: u64,
    pub public_key: BlsPublicKey,
    pub withdrawable_epoch: u64,
}

#[test]
fn test_ssz_patterns() {
    let validators = vec![
        SimpleValidator {
            balance: 32,
            public_key: BlsPublicKey::try_from([1u8; 48].try_into().unwrap()).unwrap(),
            withdrawable_epoch: 1,
        },
        SimpleValidator {
            balance: 18,
            public_key: BlsPublicKey::try_from([2u8; 48].try_into().unwrap()).unwrap(),
            withdrawable_epoch: 2,
        },
    ];
    

    ssz_rs::calculate_multi_merkle_root(leaves, proof, indices)
}
