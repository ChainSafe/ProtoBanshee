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

pub(crate) mod gadget;
pub mod table;
pub(crate) mod util;
pub mod witness;

pub mod sha256_circuit;
pub mod state_circuit;
pub mod vs_circuit;

pub const MAX_VALIDATORS: usize = 100;

pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

pub(crate) const N_BYTES_U64: usize = 8;
