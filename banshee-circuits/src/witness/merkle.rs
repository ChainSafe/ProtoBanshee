// Copyright 2023 ChainSafe Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use gadgets::impl_expr;
use strum_macros::EnumIter;

pub type MerkleTrace<F> = Vec<MerkleTraceStep<F>>;

#[derive(Clone, Debug)]
pub struct MerkleTraceStep<F> {
    pub sibling: F,
    pub sibling_index: F,
    pub node: F,
    pub index: F,
    pub into_left: F,
    pub is_left: F,
    pub is_right: F,
    pub parent: F,
    pub parent_index: F,
    pub depth: F,
}

// #[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
// pub enum LevelTag {
//     PubKeys = 0,
//     Validators
// }
// impl_expr!(LevelTag);

// impl From<LevelTag> for usize {
//     fn from(value: LevelTag) -> usize {
//         value as usize
//     }
// }
