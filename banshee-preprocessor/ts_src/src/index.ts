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

const ValidatorContainer = new ContainerType(
    {
      pubkey: ssz.Bytes32,
      activationEpoch: ssz.Uint32,
      effectiveBalance: ssz.Uint32,
    },
    {typeName: "Validator", jsonCase: "eth2"}
  );

const ValidatorNodeStruct = new ContainerType(ValidatorContainer.fields, ValidatorContainer.opts);
// The main Validator type is the 'ContainerNodeStructType' version
const ValidatorStruct = ValidatorNodeStruct;

type Validator = ValueOf<typeof ValidatorStruct>;

export const ValidatorsSsz = new ListCompositeType(ValidatorNodeStruct, 8);

// const fromHexString = (hexString: string) =>
//   Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const N = 6;
let validators: Validator[] = [];
let gindeces: bigint[] = [];

for (let i = 0; i < N; i++) {
    validators.push({
        pubkey: crypto.randomBytes(32),
        activationEpoch: i + 1,
        effectiveBalance: 32000000,
    });
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex);
    gindeces.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex)
}

console.log(validators);
let view = ValidatorsSsz.toView(validators);

// console.log(new Tree(view.node).getNodesAtDepth(4, 16, 8).map((node) => "0x" + Buffer.from(node.root).toString("hex")));
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

function draw_separator() {
    console.log('|-------|---------|--------|--------|---------|-------|--------|---------|--------|')
}

console.log();
draw_separator();
console.log('| Depth | Sibling | IsLeft | sIndex |  Node   | Index | isLeaf | Parent  | pIndex |')
draw_separator();
for (let t of trace) {
    if (t.depth != current_level) {
        draw_separator()
        current_level = t.depth;
    }
    let node = Buffer.from(t.node).toString("hex").substring(0, 7);
    let sibling = Buffer.from(t.sibling).toString("hex").substring(0, 7);
    let parent = Buffer.from(t.parent).toString("hex").substring(0, 7);
    console.log(`|   ${t.depth}   | ${sibling} |   ${t.isLeft ? 1 : 0}    |   ${t.siblingGindex.toString().padEnd(3, ' ')}  | ${node} |  ${t.nodeGindex.toString().padEnd(3, ' ')}  |   ${t.isLeaf ? 1 : 0}    | ${parent} |   ${t.parentGindex.toString().padEnd(3, ' ')}  |`)
}

let root = Buffer.from(partial_tree.root).toString("hex").substring(0, 7);
draw_separator();
console.log(`|   1   |         |   0    |        | ${root} |  1    |   0    |         |        |`)
draw_separator();

console.log("\nisValid?", areEqual(partial_tree.root, view.node.root));
