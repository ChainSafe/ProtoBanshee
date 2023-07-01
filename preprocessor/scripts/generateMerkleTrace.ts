import fs from "fs";
import path from "path";
import { bn254 } from '@noble/curves/bn254';
import { bls12_381 } from '@noble/curves/bls12-381';
import {
    ContainerType,
    ListCompositeType,
    ValueOf
} from "@chainsafe/ssz";
import {
    ssz,
} from "@lodestar/types"
import {
    BeaconState
} from "@lodestar/types/phase0"
import { createProof, ProofType, MultiProof, Node } from "@chainsafe/persistent-merkle-tree";
import crypto from "crypto";
import { serialize } from "./util";
import { createNodeFromMultiProofWithTrace, printTrace } from "./merkleTrace";


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
    { typeName: "Validator", jsonCase: "eth2" }
);

type Validator = ValueOf<typeof ValidatorContainer>;

export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, 10);

const N = 5;
let validators: Validator[] = [];
let gindices: bigint[] = [];
let validatorBaseGindices: bigint[] = [];

console.log("validators[0].gindex:", ValidatorsSsz.getPathInfo([0]).gindex);

let nonRlcGindices = [];

for (let i = 0; i < N; i++) {
    // let privKey = bls12_381.utils.randomPrivateKey();
    // let pubkey = bls12_381.getPublicKey(privKey);
    let privKey = bn254.utils.randomPrivateKey();
    let pubkey = bn254.getPublicKey(privKey);
    console.log("pubkey:", pubkey);
    const paddedPubkey = new Uint8Array(48);
    paddedPubkey.set(pubkey, 0);

    validators.push({
        pubkey: paddedPubkey,
        withdrawalCredentials: Uint8Array.from(crypto.randomBytes(32)),
        effectiveBalance: 32000000,
        slashed: false,
        activationEligibilityEpoch: i,
        activationEpoch: i + 1,
        exitEpoch: 100,
        withdrawableEpoch: 0
    });
    validatorBaseGindices.push(ValidatorsSsz.getPathInfo([i]).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'pubkey']).gindex * 2n + 1n);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    gindices.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);

    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'effectiveBalance']).gindex);
    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'slashed']).gindex);
    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'activationEpoch']).gindex);
    nonRlcGindices.push(ValidatorsSsz.getPathInfo([i, 'exitEpoch']).gindex);
}

let view = ValidatorsSsz.toView(validators);

let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, nonRlcGindices);

printTrace(partial_tree, trace);

const target_epoch = 25;

fs.writeFileSync(
    `../test_data/validators.json`,
    serialize(Array.from(validators.entries()).map(([i, validator]) => ({
        id: i,
        committee: 0,
        isActive: !validator.slashed && validator.activationEpoch <= target_epoch && target_epoch < validator.exitEpoch,
        isAttested: true,
        pubkey: Array.from(validator.pubkey),
        effectiveBalance: validator.effectiveBalance,
        slashed: validator.slashed,
        activationEpoch: validator.activationEpoch,
        exitEpoch: validator.exitEpoch,
        gindex: validatorBaseGindices[i]
    })))
);

fs.writeFileSync(
    `../test_data/committees.json`,
    serialize([
        {
            id: 0,
            accumulatedBalance: Array.from(validators).reduce((acc, validator) => acc + validator.effectiveBalance, 0),
            aggregatedPubkey: Array.from(crypto.randomBytes(48)), // TODO: aggregate pubkeys
        }
    ])
);

fs.writeFileSync(
    `../test_data/merkle_trace.json`,
    serialize(trace)
);
