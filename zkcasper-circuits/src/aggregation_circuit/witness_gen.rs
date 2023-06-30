use eth_types::Field;
use itertools::Itertools;

use super::{G1_FQ_BYTES, G1_BYTES_UNCOMPRESSED, NUM_LIMBS, LIMB_BITS};

pub struct AggregationRow<F: Field> {
    pub pk_uncompressed: [F; G1_BYTES_UNCOMPRESSED],
    pub x_limbs: [F; NUM_LIMBS],
    pub y_limbs: [F; NUM_LIMBS],
}

pub fn aggregate_pubkeys<F: Field>(bytes: &[u8]) -> AggregationRow<F> {
    assert_eq!(bytes.len(), G1_BYTES_UNCOMPRESSED);

    let two = F::from(2);
    let f256 = two.pow_const(8);

    let pubkey_uncompressed: [F; G1_BYTES_UNCOMPRESSED] = bytes
        .iter()
        .map(|&b| F::from(b as u64))
        .collect_vec()
        .try_into()
        .unwrap();

    let bytes_per_limb = LIMB_BITS / 8;

    let to_bigint = |bytes: &[F]| -> [F; NUM_LIMBS] {
        bytes
            .chunks(bytes_per_limb)
            .map(|chunk| {
                chunk
                    .iter()
                    .rev()
                    .fold(F::zero(), |acc, &byte| acc * f256 + byte)
            })
            .collect_vec()
            .try_into()
            .unwrap()
    };

    let x_limbs = to_bigint(&pubkey_uncompressed[..G1_FQ_BYTES]);
    let y_limbs = to_bigint(&pubkey_uncompressed[G1_FQ_BYTES..]);

    AggregationRow {
        pk_uncompressed: pubkey_uncompressed,
        x_limbs,
        y_limbs,
    }
}
