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

use core::hash::Hash;
use halo2_proofs::{
    arithmetic::{Field as Halo2Field, FieldExt},
    halo2curves::{
        bn256::{Fq, Fr},
        group::ff::PrimeField,
    },
};

/// Trait used to reduce verbosity with the declaration of the [`PrimeField`]
/// trait and its repr.
pub trait Field: FieldExt + Halo2Field + PrimeField<Repr = [u8; 32]> + Hash/*+ FromUniformBytes<64>*/ + Ord {
    // /// Gets the lower 128 bits of this field element when expressed
    // /// canonically.
    // fn get_lower_128(&self) -> u128 {
    //     let bytes = self.to_repr();
    //     bytes[..16]
    //         .iter()
    //         .rev()
    //         .fold(0u128, |acc, value| acc * 256u128 + *value as u128)
    // }
    // /// Gets the lower 32 bits of this field element when expressed
    // /// canonically.
    // fn get_lower_32(&self) -> u32 {
    //     let bytes = self.to_repr();
    //     bytes[..4]
    //         .iter()
    //         .rev()
    //         .fold(0u32, |acc, value| acc * 256u32 + *value as u32)
    // }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}
