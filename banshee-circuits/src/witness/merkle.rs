use gadgets::impl_expr;
use strum_macros::EnumIter;

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
    level_tag: F,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
pub enum LevelTag {
    PubKeys = 0,
    Validators
}
impl_expr!(LevelTag);

impl From<LevelTag> for usize {
    fn from(value: LevelTag) -> usize {
        value as usize
    }
}
