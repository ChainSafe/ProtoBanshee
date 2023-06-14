import {Node, BranchNode, LeafNode, Gindex} from "@chainsafe/persistent-merkle-tree";
import { SortOrder, computeMultiProofBitstrings, } from "./util";

type TraceRow = {
    node: Uint8Array;
    nodeGindex: Gindex;
    sibling: Uint8Array;
    siblingGindex: Gindex;
    isLeft: boolean;
    isRight: boolean;
    parent: Uint8Array;
    parentGindex: Gindex;
    depth: number;
};

export function createNodeFromMultiProofWithTrace(leaves: Uint8Array[], witnesses: Uint8Array[], gindices: Gindex[]): [Node, TraceRow[]] {
    if (leaves.length !== gindices.length) {
      throw new Error("Leaves length should equal gindices length");
    }
  
    const leafBitstrings = gindices.map((gindex) => gindex.toString(2));
    const witnessBitstrings = computeMultiProofBitstrings(leafBitstrings, false, SortOrder.Decreasing);
  
    if (witnessBitstrings.length !== witnesses.length) {
      throw new Error("Witnesses length should equal witnesses gindices length");
    }
  
    // Algorithm:
    // create an object which tracks key-values for each level
    // pre-load leaves and witnesses into the level object
    // level by level, starting from the bottom,
    // find the sibling, create the parent, store it in the next level up
    // the root is in level 1
    const maxLevel = Math.max(leafBitstrings[0]?.length ?? 0, witnessBitstrings[0]?.length ?? 0);
  
    const levels: Record<number, Record<string, Node>> = Object.fromEntries(
      Array.from({length: maxLevel}, (_, i) => [i + 1, {}])
    );
  
    // preload leaves and witnesses
    for (let i = 0; i < leafBitstrings.length; i++) {
      const leafBitstring = leafBitstrings[i];
      const leaf = leaves[i];
      levels[leafBitstring.length][leafBitstring] = LeafNode.fromRoot(leaf);
    }
    for (let i = 0; i < witnessBitstrings.length; i++) {
      const witnessBitstring = witnessBitstrings[i];
      const witness = witnesses[i];
      levels[witnessBitstring.length][witnessBitstring] = LeafNode.fromRoot(witness);
    }

    let trace: TraceRow[] = [];
  
    for (let i = maxLevel; i > 1; i--) {
      const level = levels[i];
      const parentLevel = levels[i - 1];
      for (const bitstring of Object.keys(level)) {
        const nodeGindex = BigInt(parseInt(bitstring, 2));
        const node = level[bitstring];
        // if the node doesn't exist, we've already processed its sibling
        if (!node) {
          continue;
        }
  
        const isLeft = bitstring[bitstring.length - 1] === "0";
        const parentBitstring = bitstring.substring(0, bitstring.length - 1);
        const parentGindex = BigInt(parseInt(parentBitstring, 2));

        const siblingBitstring = parentBitstring + (isLeft ? "1" : "0");
        const siblingGindex = BigInt(parseInt(siblingBitstring, 2));
  
        const siblingNode = level[siblingBitstring];
        if (!siblingNode) {
          throw new Error(`Sibling not found: ${siblingBitstring}`);
        }
  
        // store the parent node
        const parentNode = isLeft ? new BranchNode(node, siblingNode) : new BranchNode(siblingNode, node);
        // console.log("fst:", (isLeft ? nodeGindex : siblingGindex), Buffer.from((isLeft ? node : siblingNode).root).toString("hex"),  "snd:", (isLeft ? siblingGindex : nodeGindex), Buffer.from((isLeft ? siblingNode : node).root).toString("hex"), "hash:", parentGindex, Buffer.from(parentNode.root).toString("hex"));
        trace.push({
            node: node.root,
            nodeGindex,
            sibling: siblingNode.root,
            siblingGindex,
            isLeft: gindices.includes(isLeft ? nodeGindex : siblingGindex),
            isRight: gindices.includes(isLeft ? siblingGindex : nodeGindex),
            parent: parentNode.root,
            parentGindex,
            depth: i,
        });
        
        parentLevel[parentBitstring] = parentNode;
  
        // delete the used nodes
        delete level[bitstring];
        delete level[siblingBitstring];
      }
    }

    const root = levels[1]["1"];

    if (!root) {
      throw new Error("Internal consistency error: no root found");
    }
    return [root, trace];
  }
