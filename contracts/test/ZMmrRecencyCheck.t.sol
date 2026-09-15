// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

// INDEPENDENT cross-verification of the "no recency binding" claim.
//
// The recency argument rests on one MMR property: a leaf inserted at an OLD block stays provable
// against the CURRENT (later, larger) root. This test confirms that WITHOUT trusting the reporter's
// MMR model:
//   * A from-scratch peaks-stack MMR -- built the way substrate `pallet-mmr` actually appends leaves
//     (push each leaf as a height-0 peak; while the top two peaks share a height, merge them) --
//     is cross-checked against (a) hand-computed roots for N = 1..4 and (b) the reporter's
//     binary-decomposition model in ZMmrRecency.t.sol. Two independent implementations agreeing on
//     non-power-of-two sizes is strong evidence the model is faithful.
//   * An independently generated leaf-0 proof folds (clean-room) to that independent root.
//   * The REAL `BeefyClient.verifyMMRLeafProof` accepts leaf 0 (the oldest) against the current
//     1000-leaf root, and rejects it against an earlier 500-leaf root -- i.e. proofs are
//     root-specific, and the old leaf genuinely tracks forward to the newer root.
//   * The REAL `Verification.verifyCommitment` accepts a parachain-heads root that is 999 blocks
//     stale against the current MMR root.
//
// Run: forge test --match-path test/ZMmrRecencyCheck.t.sol -vv

import {Test} from "forge-std/Test.sol";
import {Verification} from "../src/Verification.sol";
import {BeefyClient} from "../src/BeefyClient.sol";
import {BeefyClientMock} from "./mocks/BeefyClientMock.sol";
import {VerificationWrapper} from "./mocks/VerificationWrapper.sol";
import {ScaleCodec} from "../src/utils/ScaleCodec.sol";
import {MerkleLibSubstrate} from "./utils/MerkleLib.sol";
import {MmrLib} from "./ZMmrRecency.t.sol"; // reporter's model -- imported ONLY to cross-check

contract ZMmrRecencyCheckTest is Test {
    BeefyClientMock beefyClient;
    VerificationWrapper wrapper;

    uint32 constant BRIDGE_HUB_PARA_ID = 1002;
    bytes4 encodedBridgeHubID;

    function setUp() public {
        beefyClient = new BeefyClientMock(
            3, 8, 16, 101, 0, BeefyClient.ValidatorSet(0, 0, 0x0), BeefyClient.ValidatorSet(1, 0, 0x0)
        );
        encodedBridgeHubID = ScaleCodec.encodeU32(BRIDGE_HUB_PARA_ID);
        wrapper = new VerificationWrapper();
    }

    function _merge(bytes32 l, bytes32 r) internal pure returns (bytes32 v) {
        assembly {
            mstore(0x00, l)
            mstore(0x20, r)
            v := keccak256(0x00, 0x40)
        }
    }

    // --- Independent MMR root: peaks-stack append, exactly how pallet-mmr pushes leaves. ---
    function _mmrRootAppend(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256 n = leaves.length;
        bytes32[] memory ph = new bytes32[](256); // peak hashes (stack)
        uint256[] memory hh = new uint256[](256); // peak heights (stack)
        uint256 top = 0;
        for (uint256 i = 0; i < n; i++) {
            ph[top] = leaves[i];
            hh[top] = 0;
            top++;
            while (top >= 2 && hh[top - 1] == hh[top - 2]) {
                uint256 h = hh[top - 1];
                bytes32 m = _merge(ph[top - 2], ph[top - 1]);
                top -= 2;
                ph[top] = m;
                hh[top] = h + 1;
                top++;
            }
        }
        // bag peaks right-to-left: acc = merge(p0, merge(p1, merge(p2, ...)))
        bytes32 acc = ph[top - 1];
        for (uint256 i = top - 1; i > 0; i--) {
            acc = _merge(ph[i - 1], acc);
        }
        return acc;
    }

    // Perfect-subtree root over leaves[from, from+size).
    function _subtree(bytes32[] memory leaves, uint256 from, uint256 size)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory lvl = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            lvl[i] = leaves[from + i];
        }
        while (lvl.length > 1) {
            bytes32[] memory nxt = new bytes32[](lvl.length / 2);
            for (uint256 i = 0; i < nxt.length; i++) {
                nxt[i] = _merge(lvl[2 * i], lvl[2 * i + 1]);
            }
            lvl = nxt;
        }
        return lvl[0];
    }

    function _highestPow2LE(uint256 n) internal pure returns (uint256 p, uint256 log2) {
        p = 1;
        log2 = 0;
        while (p * 2 <= n) {
            p *= 2;
            log2++;
        }
    }

    // Suffix MMR root over leaves[from, end): the same bagging operation, so == append root of it.
    function _suffixRoot(bytes32[] memory leaves, uint256 from) internal pure returns (bytes32) {
        uint256 size = leaves.length - from;
        bytes32[] memory sub = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            sub[i] = leaves[from + i];
        }
        return _mmrRootAppend(sub);
    }

    // Independently generated proof for leaf 0 against the full MMR of `leaves`.
    // Leaf 0 is always the leftmost leaf of the leftmost (largest) peak, so at every inner level it
    // is the left child (sibling on the RIGHT), and the remaining peaks all sit to its right.
    function _leaf0Proof(bytes32[] memory leaves)
        internal
        pure
        returns (bytes32[] memory proof, uint256 order)
    {
        uint256 n = leaves.length;
        (uint256 S0, uint256 depth) = _highestPow2LE(n);
        uint256 extra = n > S0 ? 1 : 0;
        proof = new bytes32[](depth + extra);
        order = 0; // every sibling is on the RIGHT for leaf 0 -> all order bits are 0
        for (uint256 d = 0; d < depth; d++) {
            // sibling at level d = perfect-subtree root over leaves[2^d, 2^(d+1))
            proof[d] = _subtree(leaves, (uint256(1) << d), (uint256(1) << d));
        }
        if (extra == 1) {
            proof[depth] = _suffixRoot(leaves, S0); // bag of the peaks to the right of leaf 0
        }
    }

    // Clean-room fold mirroring MMRProof.verifyLeafProof (order bit 0 => sibling on the right).
    function _fold(bytes32 leaf, bytes32[] memory proof, uint256 order)
        internal
        pure
        returns (bytes32 acc)
    {
        acc = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if ((order >> i) & 1 == 1) {
                acc = _merge(proof[i], acc);
            } else {
                acc = _merge(acc, proof[i]);
            }
        }
    }

    // Reporter's model assembled into a single root, used only for cross-checking.
    function _mmrRootReporter(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256[] memory sizes = MmrLib.peakSizes(leaves.length);
        uint256 nn = sizes.length;
        bytes32[] memory peaks = new bytes32[](nn);
        uint256 off = 0;
        for (uint256 i = 0; i < nn; i++) {
            peaks[i] = MmrLib.peakRoot(leaves, off, sizes[i]);
            off += sizes[i];
        }
        bytes32 acc = peaks[nn - 1];
        for (uint256 i = nn - 1; i > 0; i--) {
            acc = MmrLib.merge(peaks[i - 1], acc);
        }
        return acc;
    }

    function _genericLeaves(uint256 n) internal pure returns (bytes32[] memory leaves) {
        leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = keccak256(abi.encodePacked("leaf:", i));
        }
    }

    // ------------------------------------------------------------------
    // A. The independent MMR model is correct: hand vectors + agreement with
    //    the reporter's model + self-consistency of the leaf-0 proof.
    // ------------------------------------------------------------------
    function test_A_modelIsFaithful() public pure {
        // Hand-computed roots.
        bytes32 l0 = keccak256(abi.encodePacked("leaf:", uint256(0)));
        bytes32 l1 = keccak256(abi.encodePacked("leaf:", uint256(1)));
        bytes32 l2 = keccak256(abi.encodePacked("leaf:", uint256(2)));
        bytes32 l3 = keccak256(abi.encodePacked("leaf:", uint256(3)));

        assertEq(_mmrRootAppend(_genericLeaves(1)), l0, "N=1");
        assertEq(_mmrRootAppend(_genericLeaves(2)), _merge(l0, l1), "N=2");
        assertEq(_mmrRootAppend(_genericLeaves(3)), _merge(_merge(l0, l1), l2), "N=3");
        assertEq(
            _mmrRootAppend(_genericLeaves(4)), _merge(_merge(l0, l1), _merge(l2, l3)), "N=4"
        );

        // Two independent implementations must agree, including non-powers-of-two.
        uint256[7] memory sizes = [uint256(1), 2, 3, 4, 5, 13, 1000];
        for (uint256 k = 0; k < sizes.length; k++) {
            bytes32[] memory leaves = _genericLeaves(sizes[k]);
            bytes32 mine = _mmrRootAppend(leaves);
            assertEq(mine, _mmrRootReporter(leaves), "append root == reporter root");

            // My independently generated leaf-0 proof folds back to my independent root.
            (bytes32[] memory proof, uint256 order) = _leaf0Proof(leaves);
            assertEq(_fold(leaves[0], proof, order), mine, "leaf-0 proof folds to root");
        }
    }

    // ------------------------------------------------------------------
    // B. Append-only recency through the REAL contract verifier: the oldest
    //    leaf verifies against the CURRENT root, and proofs are root-specific.
    // ------------------------------------------------------------------
    function test_B_oldestLeafVerifiesAgainstCurrentRootViaRealVerifier() public {
        bytes32[] memory leaves1000 = _genericLeaves(1000);
        bytes32 root1000 = _mmrRootAppend(leaves1000);

        bytes32[] memory leaves500 = _genericLeaves(500);
        bytes32 root500 = _mmrRootAppend(leaves500);

        // The MMR genuinely advanced: appending leaves 500..999 changed the root.
        assertTrue(root500 != root1000, "root moved forward as leaves were appended");

        (bytes32[] memory proof1000, uint256 order1000) = _leaf0Proof(leaves1000);
        (bytes32[] memory proof500, uint256 order500) = _leaf0Proof(leaves500);

        // Against the CURRENT (1000-leaf) root: leaf 0 -- the oldest -- verifies.
        beefyClient.setLatestMMRRoot(root1000);
        assertTrue(
            beefyClient.verifyMMRLeafProof(leaves1000[0], proof1000, order1000),
            "oldest leaf verifies against current root"
        );
        // The 500-era proof does NOT verify against the current root.
        assertFalse(
            beefyClient.verifyMMRLeafProof(leaves500[0], proof500, order500),
            "stale-era proof must not verify against the newer root"
        );

        // Against the earlier (500-leaf) root: the 500-era proof verifies, the 1000 one does not.
        beefyClient.setLatestMMRRoot(root500);
        assertTrue(
            beefyClient.verifyMMRLeafProof(leaves500[0], proof500, order500),
            "leaf 0 verifies against its own era's root"
        );
        assertFalse(
            beefyClient.verifyMMRLeafProof(leaves1000[0], proof1000, order1000),
            "1000-era proof must not verify against the earlier root"
        );
    }

    // ------------------------------------------------------------------
    // C. End-to-end: the REAL verifyCommitment accepts a 999-block-stale
    //    parachain-heads root against the current MMR root.
    // ------------------------------------------------------------------
    function _leaf(uint256 i, bytes32 headsRoot) internal view returns (bytes32) {
        return wrapper.createMMRLeaf(_partial(i), headsRoot);
    }

    function _partial(uint256 i) internal pure returns (Verification.MMRLeafPartial memory) {
        return Verification.MMRLeafPartial({
            version: 0,
            parentNumber: uint32(30_000_000 + i),
            parentHash: keccak256(abi.encodePacked("relay", i)),
            nextAuthoritySetID: 5000,
            nextAuthoritySetLen: 600,
            nextAuthoritySetRoot: keccak256("authset")
        });
    }

    function test_C_verifyCommitmentAcceptsA999BlockStaleHeadsRoot() public {
        // An ancient forged BridgeHub header carrying the attacker's commitment.
        bytes32 commitment = keccak256("a commitment from long ago");
        Verification.DigestItem[] memory d = new Verification.DigestItem[](1);
        d[0] = Verification.DigestItem({
            kind: 0,
            consensusEngineID: 0x00000000,
            data: bytes.concat(hex"01", commitment)
        });
        Verification.ParachainHeader memory header = Verification.ParachainHeader({
            parentHash: keccak256("ancient-parent"),
            number: 1,
            stateRoot: keccak256("ancient-state"),
            extrinsicsRoot: keccak256("ancient-extrinsics"),
            digestItems: d
        });

        // The ancient parachain-heads tree (BridgeHub's genuine leaf at index 1).
        bytes32[] memory heads = new bytes32[](13);
        for (uint256 i = 0; i < 13; i++) {
            heads[i] = keccak256(abi.encodePacked("ancient-parahead:", i));
        }
        heads[1] = wrapper.createParachainHeaderMerkleLeaf(encodedBridgeHubID, header);
        bytes32 headsRoot = MerkleLibSubstrate.rootFromLeaves(heads);
        bytes32[] memory headProof = MerkleLibSubstrate.genProof(heads, 1);

        // 1000 relay blocks of MMR history; the ancient headsRoot is leaf 0, 999 blocks stale.
        bytes32[] memory leaves = new bytes32[](1000);
        leaves[0] = _leaf(0, headsRoot);
        for (uint256 i = 1; i < 1000; i++) {
            leaves[i] = _leaf(i, keccak256(abi.encodePacked("headsRoot", i)));
        }
        bytes32 root = _mmrRootAppend(leaves);
        (bytes32[] memory mmrProof, uint256 mmrOrder) = _leaf0Proof(leaves);

        // Sanity: my independent proof folds to my independent root.
        assertEq(_fold(leaves[0], mmrProof, mmrOrder), root, "mmr proof folds to root");

        beefyClient.setLatestMMRRoot(root);

        bool accepted = Verification.verifyCommitment(
            address(beefyClient),
            encodedBridgeHubID,
            commitment,
            Verification.Proof({
                header: header,
                headProof: Verification.HeadProof({pos: 1, width: 13, proof: headProof}),
                leafPartial: _partial(0),
                leafProof: mmrProof,
                leafProofOrder: mmrOrder
            }),
            true
        );
        assertTrue(accepted, "a 999-block-stale parachain-heads root is accepted");

        emit log_named_uint("MMR leaves at verification time", 1000);
        emit log_named_uint("leaf index (relay block) used", 0);
        emit log_named_uint("blocks of staleness accepted", 999);
    }
}
