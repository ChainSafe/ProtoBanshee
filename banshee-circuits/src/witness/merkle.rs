
pub type MerkleTrace<F> = Vec<MerkleTraceStep<F>>;

#[derive(Clone, Debug)]
pub struct MerkleTraceStep<F> {
    sibling: F,
    sibling_index: F,
    node: F,
    index: F,
    is_leaf: F,
    parent: F,
    parent_index: F,
    depth: F,
}
