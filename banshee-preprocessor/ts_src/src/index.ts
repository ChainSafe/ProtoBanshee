import {
    ContainerType,
    ContainerNodeStructType,
    ListCompositeType,
    ValueOf
  } from "@chainsafe/ssz";
import {
    ssz,
} from "@lodestar/types"
import {
    Validator as BeaconValidator,
} from "@lodestar/types/phase0"
import {Node, createProof, ProofType, createNodeFromProof, Tree, BranchNode, LeafNode, Gindex, MultiProof} from "@chainsafe/persistent-merkle-tree";
import { createNodeFromMultiProofWithTrace } from "./merkleTrace";
import crypto from "crypto";

const ToyValidatorContainer = new ContainerType(
    {
      pubkey: ssz.Bytes32,
      activationEpoch: ssz.Uint32,
      effectiveBalance: ssz.Uint32,
    },
    {typeName: "Validator", jsonCase: "eth2"}
  );

  const ValidatorContainer = new ContainerType(
    {
        pubkey: ssz.Bytes48,
        withdrawalCredentials: ssz.Bytes32,
        effectiveBalance: ssz.UintNum64,
        slashed: ssz.Boolean,
        activationEligibilityEpoch: ssz.EpochInf,
        activationEpoch: ssz.EpochInf,
        exitEpoch: ssz.EpochInf,
        withdrawableEpoch: ssz.EpochInf,
    },
    {typeName: "Validator", jsonCase: "eth2"}
  );

type Validator = ValueOf<typeof ValidatorContainer>;

export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, 10);

// const fromHexString = (hexString: string) =>
//   Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const N = 8;
let validators: Validator[] = [];
let gindeces: bigint[] = [];

for (let i = 0; i < N; i++) {
    // validators.push({
    //     pubkey: crypto.randomBytes(32),
    //     activationEpoch: i + 1,
    //     effectiveBalance: 32000000,
    // });
    validators.push({
        pubkey: crypto.randomBytes(48),
        activationEpoch: i + 1,
        effectiveBalance: 32000000,
        withdrawalCredentials: crypto.randomBytes(32),
        slashed: false,
        activationEligibilityEpoch: i,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n + 1n);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);
}
let view = ValidatorsSsz.toView(validators);

// function printTree(tree: Node, depth: number = 0) {
//     console.log(" ".repeat(depth), depth, "0x" + Buffer.from(tree.root).toString("hex"), tree.isLeaf() ? "leaf" : "");
//     if (tree.isLeaf())
//         return;
//     if (tree.left) {
//         printTree(tree.left, depth + 1,);
//     }
//     if (tree.right) {
//         printTree(tree.right, depth + 1);
//     }
// }
// printTree(view.node);


console.log('gindeces:', gindeces);

let proof = createProof(view.node, {type: ProofType.multi, gindices: gindeces}) as MultiProof; 
// console.log(proof);

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);


let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices);

let current_level = trace[0].depth;
let row_index = 0;

function draw_separator() {
    console.log('|-----||-------|---------|--------|---------|-------|--------|--------|---------|--------|')
}

console.log();
draw_separator();
console.log('| Row || Depth | Sibling | sIndex |  Node   | Index | IsLeaf | IsLeft | Parent  | pIndex |')
draw_separator();
for (let t of trace) {
    if (t.depth != current_level) {
        draw_separator()
        current_level = t.depth;
    }
    let node = Buffer.from(t.node).toString("hex").substring(0, 7);
    let sibling = Buffer.from(t.sibling).toString("hex").substring(0, 7);
    let parent = Buffer.from(t.parent).toString("hex").substring(0, 7);
    console.log(`| ${(row_index++).toString().padEnd(3, ' ')} ||  ${t.depth.toString().padEnd(2, ' ')}   | ${sibling} |   ${t.siblingGindex.toString().padEnd(3, ' ')}  | ${node} |  ${t.nodeGindex.toString().padEnd(3, ' ')}  |   ${t.isLeaf ? 1 : 0}    |   ${t.isLeft ? 1 : 0}    | ${parent} |   ${t.parentGindex.toString().padEnd(3, ' ')}  |`)
}

let root = Buffer.from(partial_tree.root).toString("hex").substring(0, 7);
draw_separator();
console.log(`| ${(++row_index).toString().padEnd(3, ' ')} ||   1   |         |        | ${root} |  1    |   0    |        |         |        |`)
draw_separator();

console.log("\nisValid?", areEqual(partial_tree.root, view.node.root));
