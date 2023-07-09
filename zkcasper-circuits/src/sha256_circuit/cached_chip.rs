use std::collections::HashMap;

use eth_types::Field;
use halo2_base::Context;
use halo2_proofs::{
    circuit::{self, Region},
    plonk::Error,
};

use crate::witness::HashInput;

use super::sha256_chip::{AssignedHashResult, Sha256Chip};

#[derive(Debug)]
pub struct CachedSha256Chip<'a, F: Field> {
    pub inner: Sha256Chip<'a, F>,
    cache: HashMap<HashInput<u8>, AssignedHashResult<F>>,
}

impl<'a, F: Field> CachedSha256Chip<'a, F> {
    pub fn new(chip: Sha256Chip<'a, F>) -> Self {
        Self {
            inner: chip,
            cache: HashMap::new(),
        }
    }

    pub fn digest(
        &mut self,
        input: impl Into<HashInput<u8>>,
        ctx: &mut Context<F>,
        region: &mut Region<'_, F>,
        assigned_advices: &mut HashMap<(usize, usize), (circuit::Cell, usize)>,
    ) -> Result<AssignedHashResult<F>, Error> {
        let input = input.into();
        if let Some(result) = self.cache.get(&input) {
            return Ok(result.clone());
        }

        let result = self.inner.digest(input.clone(), ctx, region)?;
        self.cache.insert(input, result.clone());
        Ok(result)
    }
}
