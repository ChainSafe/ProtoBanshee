use crate::{table::{validators_table, state_table::StateTable}, util::ConstrainBuilderCommon, MAX_VALIDATORS};

pub mod cell_manager;
use cell_manager::CellManager;

pub mod constraint_builder;
use constraint_builder::ConstraintBuilder;

pub mod merkle_tree;
use merkle_tree::TreeLevel;

use crate::{
    gadget::IsEqualGadget,
    table::{sha256_table, LookupTable, SHA256Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self, MerkleTrace},
};
use eth_types::*;
use gadgets::{
    batched_is_zero::{BatchedIsZeroChip, BatchedIsZeroConfig},
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::{not, Expr},
};
use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Instance,
        SecondPhase, Selector, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::{
    fmt::format,
    iter,
    marker::PhantomData,
    ops::{Add, Mul},
    vec,
};

pub const CHUNKS_PER_VALIDATOR: usize = 8;
pub const USED_CHUNKS_PER_VALIDATOR: usize = 5;
pub const TREE_DEPTH: usize = 10; // ceil(log2(TREE_MAX_LEAVES))
pub const TREE_LEVEL_AUX_COLUMNS: usize = 1;

pub const PUBKEYS_LEVEL: usize = 10;
pub const VALIDATORS_LEVEL: usize = PUBKEYS_LEVEL - 1;

#[derive(Clone, Debug)]
pub struct StateSSZCircuitConfig<F: Field> {
    tree: [TreeLevel<F>; TREE_DEPTH - 1],
    sha256_table: SHA256Table,
    pub state_table: [StateTable; 2],
    
    // state_root: Column<Instance>
}

pub struct StateSSZCircuitArgs {
    pub sha256_table: SHA256Table,
}

impl<F: Field> SubCircuitConfig<F> for StateSSZCircuitConfig<F> {
    type ConfigArgs = StateSSZCircuitArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let sha256_table = args.sha256_table;

        let pubkeys_level = TreeLevel::configure(meta, PUBKEYS_LEVEL, 0, 3);
        let validators_level = TreeLevel::configure(meta, VALIDATORS_LEVEL, 0, 0);

        let state_table: [StateTable; 2] = [
            pubkeys_level.clone().into(),
            validators_level.clone().into(),
        ];

        let mut tree = vec![pubkeys_level, validators_level];

        let mut padding = 0;
        for i in (2..=TREE_DEPTH-2).rev() {
            padding = padding * 2 + 1;
            let level = TreeLevel::configure(meta, i, 0, padding);
            tree.push(level);
        }

        let mut tree: [_; TREE_DEPTH - 1] = tree.into_iter().rev().collect_vec().try_into().unwrap();

        // Annotate circuit
        sha256_table.annotate_columns(meta);
        state_table.iter().for_each(|table| table.annotate_columns(meta));

        for depth in (2..TREE_DEPTH).rev() {
            let depth = depth - 1;
            let level = &tree[depth];
            let next_level = &tree[depth - 1];

            meta.create_gate("tree_level boolean checks", |meta| {
                let selector = level.selector(meta);
                let mut cb = ConstraintBuilder::new();
                cb.require_boolean("into_left is boolean", level.into_left(meta));
                cb.gate(selector)
            });

            meta.lookup_any("hash(node, sibling) == next_level.node", |meta| {
                let selector = level.selector(meta);
                let into_node = level.into_left(meta);
                let node = level.node(meta);
                let sibling = level.sibling(meta);
                let parent = next_level.node(meta);
                sha256_table.build_lookup(meta, selector * into_node, node, sibling, parent)
            });

            meta.lookup_any("hash(node, sibling) = next_level.sibling", |meta| {
                let selector = level.selector(meta);
                let into_sibling: Expression<F> = not::expr(level.into_left(meta));
                let node = level.node(meta);
                let sibling = level.sibling(meta);
                let parent = next_level.sibling_at(level.padding().add(1).mul(-1), meta);
                sha256_table.build_lookup(
                    meta,
                    selector * into_sibling,
                    node,
                    sibling,
                    parent,
                )
            });
        }

        StateSSZCircuitConfig {
            tree,
            sha256_table,
            state_table,
        }
    }

    fn annotate_columns_in_region(&self, region: &mut Region<'_, F>) {
        self.state_table.iter().for_each(|table| table.annotate_columns_in_region(region));
        self.sha256_table.annotate_columns_in_region(region);
        for level in self.tree.iter() {
            level.annotate_columns_in_region(region);
        }
    }
}

impl<F: Field> StateSSZCircuitConfig<F> {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &MerkleTrace,
        challenge: Value<F>,
    ) -> Result<usize, Error> {
        let trace_by_depth = witness.trace_by_levels();

        let max_rows = trace_by_depth
            .iter()
            .map(|steps| steps.len())
            .max()
            .unwrap();

        layouter.assign_region(
            || "state ssz circuit",
            |mut region| {
                self.annotate_columns_in_region(&mut region);

                // filter out the first (root) level, state root is assigned seperately into instance column.
                let trace_by_depth = trace_by_depth.clone().into_iter().filter(|e| e[0].depth != 1).collect_vec();
                for (level, steps) in self.tree.iter().zip(trace_by_depth) {
                    level.assign_with_region(&mut region, steps, challenge)?;
                }

                Ok(())
            },
        );

        Ok(max_rows)
    }
}

/// Circuit for verify Merkle-multi proof of the SSZ Merkelized `BeaconState`
#[derive(Clone, Default, Debug)]
pub struct StateSSZCircuit<F: Field> {
    trace: MerkleTrace,
    _f: PhantomData<F>,
}

impl<F: Field> StateSSZCircuit<F> {
    pub fn new(trace: MerkleTrace) -> Self {
        Self {
            trace,
            _f: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for StateSSZCircuit<F> {
    type Config = StateSSZCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.merkle_trace.clone())
    }

    fn unusable_rows() -> usize {
        todo!()
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        todo!()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<F, Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let num_rows = config.assign(layouter, &self.trace, challenges.sha256_input())?;

        println!("state ssz circuit rows: {}", num_rows);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sha256_circuit::{Sha256Circuit, Sha256CircuitConfig},
        witness::{MerkleTrace, StateEntry},
    };
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::Circuit,
    };
    use itertools::Itertools;
    use std::{fs, marker::PhantomData};

    #[derive(Debug, Clone)]
    struct TestStateSSZ<F: Field> {
        state: Vec<StateEntry>,
        state_circuit: StateSSZCircuit<F>,
        _f: PhantomData<F>,
    }

    impl<F: Field> Circuit<F> for TestStateSSZ<F> {
        type Config = (StateSSZCircuitConfig<F>, Challenges<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let sha256_table = SHA256Table::construct(meta);

            let config = {
                StateSSZCircuitConfig::new(
                    meta,
                    StateSSZCircuitArgs {
                        sha256_table,
                    },
                )
            };

            (config, Challenges::construct(meta))
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenge = config.1.sha256_input();
            let hash_inputs = self.state_circuit.trace.sha256_inputs();
            config
                .0
                .sha256_table
                .dev_load(&mut layouter, &hash_inputs, challenge.clone())?;
            self.state_circuit.synthesize_sub(
                &config.0,
                &config.1.values(&mut layouter),
                &mut layouter,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_state_ssz_circuit() {
        let k = 10;
        let state: Vec<StateEntry> =
            serde_json::from_slice(&fs::read("../test_data/validators.json").unwrap()).unwrap();
        let merkle_trace: MerkleTrace =
            serde_json::from_slice(&fs::read("../test_data/merkle_trace.json").unwrap()).unwrap();

        let circuit = TestStateSSZ::<Fr> {
            state,
            state_circuit: StateSSZCircuit::new(merkle_trace),
            _f: PhantomData,
        };

        let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
