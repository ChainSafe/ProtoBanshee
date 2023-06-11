use halo2_proofs::arithmetic::Field;

/// Represent a sequence of hashes in a path inside Merkle tree, it can be full
/// (with leaf) or truncated and being padded to an "empty" leaf node,
/// according to the hash_type. It would be used for the layout of Merkle tree
/// circuit
#[derive(Clone, Debug)]
pub struct MerklePath<F: Field> {
    /// generalized indices of the nodes in the path
    pub g_indices: Vec<u64>,
    /// hashes from beginning of path, from the root of MPT to leaf node
    pub hashes: Vec<F>,
    /// the cached traces for calculated all hashes required in verifing a MPT path,
    /// include the leaf hashing      
    pub hash_traces: Vec<(F, F, F)>,
}
