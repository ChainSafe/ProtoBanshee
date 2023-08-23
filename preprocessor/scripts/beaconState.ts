import fs from "fs";
import {getClient } from "@lodestar/api";
import {config} from "@lodestar/config/default";
import {
    ssz, 
    BLSPubkey, 
    ValidatorIndex
} from "@lodestar/types";
import {fromHex} from "@lodestar/utils"
import {BeaconStateAllForks } from "@lodestar/state-transition";
import {
    ContainerType,
    ListCompositeType,
    ValueOf
} from "@chainsafe/ssz";
import { createProof, ProofType, MultiProof } from "@chainsafe/persistent-merkle-tree";
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex } from "@noble/curves/abstract/utils";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { g1PointToLeBytes as g1PointToBytesLE, serialize, chunkArray } from "./util";
import { createNodeFromMultiProofWithTrace } from "./merkleTrace";


// Testing Constants
const N_VALIDATORS_COUNT = 100;
const VALIDATOR_LIMIT = 1099511627776;

const N_VALIDATORS = parseInt(process.argv[2]) || 5;
const N_COMMITTEES = parseInt(process.argv[3]) || 1;

// convenience functions for operations for beacon state collection and parsing
// the below function is pulled from lodestar/ 
export function getPubkeysForIndices(
    validators: BeaconStateAllForks["validators"],
    indexes: ValidatorIndex[]
  ): BLSPubkey[] {
    const validatorsLen = validators.length; // Get once, it's expensive
  
    const pubkeys: BLSPubkey[] = [];
    for (let i = 0, len = indexes.length; i < len; i++) {
      const index = indexes[i];
      if (index >= validatorsLen) {
        throw Error(`validatorIndex ${index} too high. Current validator count ${validatorsLen}`);
      }
  
      // NOTE: This could be optimized further by traversing the tree optimally with .getNodes()
      const validator = validators.getReadonly(index);
      pubkeys.push(validator.pubkey);
    }
  
    return pubkeys;
  }

// sepolia endpoint
// const api = getClient({baseUrl: "https://lodestar-sepolia.chainsafe.io"}, {config});
// sepolia beacon node endpoint
const api = getClient({baseUrl: "http://3.133.148.86:80"}, {config});

async function beaconstateApi(slot: string) {
    return await api.debug
    .getStateV2(
            slot,
            "ssz"
        )
    .then((res) => {
        if (res.ok) {
            return res.response;
        } else {
            // console.error(res.status, res.error.code, res.error.message);
            return new Uint8Array;
        }
    });
}

let beaconstateSsz = await beaconstateApi("head");
let beaconstate = ssz.capella.BeaconState.deserialize(beaconstateSsz);
let beaconstateJson = ssz.capella.BeaconState.toJson(beaconstate);
let beaconstateDeserialized = ssz.capella.BeaconState.deserializeToViewDU(beaconstateSsz);

//----------------- Committees -----------------//

const getBlock = await 
    api.beacon
    .getBlock(
        "head")
    .then((res) => {
        if (res.ok) {
            return res.response;
        } else {
            console.error(res.status, res.error.code, res.error.message);
            return new Uint8Array;
        }
    });

let headBlock = getBlock;
// get current head slot and corresponding epochs
let headSlot = headBlock.data.message.slot
let headEpoch = headBlock.data.message.body.attestations[0].data.target.epoch
let targetEpoch = headEpoch-1;

let pubKeyPoints: ProjPointType<bigint>[] = [];

async function getEpochCommitteeApi(stateId: number, epoch?: number) {
    return await api.beacon
    .getEpochCommittees(
            stateId,
            {"epoch": epoch}
        )
    .then((res) => {
        if (res.ok) {
            return res.response;
        } else {
            // console.error(res.status, res.error.code, res.error.message);
            return undefined;
        }
    });
}

// passing epoch number precedes the slot parameter.
// getEpochCommittees includes validator shuffling
let committee = await getEpochCommitteeApi(headSlot, targetEpoch);

for (i=0;i<committee.data.length;i++) {
    // gets all pubkeys of validators in committee.data.validators array as a Point.
    pubKeyPoints.push(getPubkeysForIndices(beaconstateDeserialized.validators, committee.data[i].validators).map(bytes => bls12_381.G1.ProjectivePoint.fromHex(bytesToHex(bytes))));
}

// ------------ Pubkeys ------------ //

pubKeyPoints = pubKeyPoints.flat(1);
const committeePubkeys = chunkArray(pubKeyPoints, pubKeyPoints.length);
const aggregatedPubKeys = committeePubkeys.map((pubKeys) => bls12_381.aggregatePublicKeys(pubKeys));
let bytesPubkeys = aggregatedPubKeys.map((aggPubkey) => Array.from(g1PointToBytesLE(aggPubkey, false)));

// console.log("bytesPubkeys: ", bytesPubkeys);
// console.log("serialize bytespubkeys: ", serialize(bytesPubkeys));

fs.writeFileSync(
    `../test_data/sepolia_aggregated_pubkeys.json`,
    serialize(bytesPubkeys)
);

// ------------ Validators ------------ // 

type Validator = ValueOf<typeof ValidatorContainer>;
let validators: Validator[] = [];
let validatorBaseGindices: bigint[] = [];
let gindices: bigint[] = [];
// the gindices of the fields that are <= 31 bytes
let nonRlcGindices = [];

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
    { 
        typeName: "Validator",
        jsonCase: "eth2" 
    }
);

export const ValidatorsSsz = new ListCompositeType(ValidatorContainer, VALIDATOR_LIMIT);

// for loop in which the size is N_VALIDATORS * N_COMMITTEES
for (let i=0; i<N_VALIDATORS * N_COMMITTEES;i++) {
    let pubkey = fromHex(beaconstateJson.validators[i].pubkey);
    const paddedPubkey = new Uint8Array(48);
    paddedPubkey.set(pubkey, 0);

    validators.push({
        pubkey: paddedPubkey,
        withdrawalCredentials: fromHex(beaconstateJson.validators[i].withdrawal_credentials),
        effectiveBalance: beaconstateJson.validators[i].effective_balance,
        slashed: beaconstateJson.validators[i].slashed,
        activationEligibilityEpoch: beaconstateJson.validators[i].activation_eligibility_epoch,
        activationEpoch: beaconstateJson.validators[i].activation_epoch,
        exitEpoch: beaconstateJson.validators[i].exit_epoch,
        withdrawableEpoch: beaconstateJson.validators[i].withdrawable_epoch
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

fs.writeFileSync(
    `../test_data/sepolia_validators.json`,
    serialize(Array.from(validators.entries()).map(([i, v]) => ({
        id: i,
        shufflePos: i,
        committee: Math.floor(i / N_VALIDATORS),
        isActive: !v.slashed && v.activationEpoch <= targetEpoch && targetEpoch < v.exitEpoch,
        isAttested: true,
        pubkey: Array.from(v.pubkey),
        pubkeyUncompressed: Array.from(g1PointToBytesLE(pubKeyPoints[i], false)),
        effectiveBalance: v.effectiveBalance,
        slashed: v.slashed,
        activationEpoch: v.activationEpoch,
        exitEpoch: v.exitEpoch,
        gindex: validatorBaseGindices[i]
    })))
);

//----------------- State tree -----------------//

let proof = createProof(view.node, { type: ProofType.multi, gindices: gindices }) as MultiProof;

const areEqual = (first: Uint8Array, second: Uint8Array) =>
    first.length === second.length && first.every((value, index) => value === second[index]);

let [partial_tree, trace] = createNodeFromMultiProofWithTrace(proof.leaves, proof.witnesses, proof.gindices, nonRlcGindices);

// printTrace(partial_tree, trace);

// console.log("proof: ", proof)
// console.log("trace: ", serialize(trace))

fs.writeFileSync(
    `../test_data/sepolia_beacon_state.json`,
    serialize(trace)
)

// ------------ Attestations ------------ //

type Attestations = ValueOf<typeof ssz.phase0.BeaconBlockBody.fields.attestations>;
let attestations: Attestations = [];

async function getBlockAttestationApi(slot: number) {
    return await api.beacon
    .getBlockAttestations(
            slot
        )
    .then((res) => {
        if (res.ok) {
            return res.response;
        } else {
            // console.error(res.status, res.error.code, res.error.message);
            return undefined;
        }
    });
}

// get all blocks within a target epoch with known slot id's for corresponding epoch.
for (var i=headSlot; ; i--) {
    let blockAttestation = await getBlockAttestationApi(i);
    if (blockAttestation == undefined) {
        // console.log("empty slot");
        continue;
    };
    // set headEpoch -1 to have TARGET_EPOCH = head target epoch - 1.
    if (blockAttestation.data[0].data.target.epoch == targetEpoch) {
        let data = {
            slot: blockAttestation.data[0].data.slot,
            index: blockAttestation.data[0].data.index,
            beaconBlockRoot: blockAttestation.data[0].data.beaconBlockRoot,
            source: {
                epoch: blockAttestation.data[0].data.source.epoch,
                root: blockAttestation.data[0].data.source.root
            },
            target: {
                epoch: blockAttestation.data[0].data.target.epoch,
                root: blockAttestation.data[0].data.target.root
            }
        };

        attestations.push({
            aggregationBits: blockAttestation.data[0].aggregationBits,
            data: data,
            signature: blockAttestation.data[0].signature
        });
    }

    // keeps running the loop until the source epoch == target epoch -2; which will confirm that the loop has run for the entire target epoch.
    if (blockAttestation.data[0].data.source.epoch == targetEpoch-2) {
        break;
    }

};

let attestationJson = ssz.phase0.BeaconBlockBody.fields.attestations.toJson(attestations);

// console.log("attestations: ", attestationJson);

fs.writeFileSync(
    `../test_data/sepolia_attestations.json`,
    JSON.stringify(attestationJson)
);
