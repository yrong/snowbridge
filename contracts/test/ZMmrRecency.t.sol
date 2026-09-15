// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

// Demonstrates that `Verification.verifyCommitment` places NO recency or size binding on the MMR
// leaf it accepts: the OLDEST leaf of a large MMR verifies against the CURRENT root just as well
// as the newest one.
//
// An MMR is append-only, so every leaf ever inserted stays provable against every later root. On
// the Solidity side nothing narrows that:
//   - `MMRProof.verifyLeafProof(root, leafHash, proof, proofOrder)` takes no leaf index and no MMR
//     size; it just folds `proof` with a free ordering bitfield and compares to the root.
//   - `Verification.createMMRLeaf` hashes `leafPartial.parentNumber` into the leaf but nothing ever
//     compares it to anything.
//
// Consequence for the parachain-heads forgery: the attacker may use the `parachainHeadsRoot` of ANY
// historical relay block, not just the current one. The precondition (a parachain in the BEEFY set
// whose head data is 59 bytes) therefore only has to have held ONCE, at any point in history.
//
// The MMR here is built exactly like substrate's `pallet-mmr`: nodes are keccak(left ++ right) with
// no domain separation, peaks are the perfect subtrees given by the binary decomposition of the
// leaf count, and the root is the right-to-left bagging of those peaks
// (root = merge(p0, merge(p1, merge(p2, ...)))), matching `bag_rhs_peaks`.
//
// Run: forge test --match-path test/ZMmrRecency.t.sol -vv

import {Test} from "forge-std/Test.sol";
import {Verification} from "../src/Verification.sol";
import {BeefyClient} from "../src/BeefyClient.sol";
import {BeefyClientMock} from "./mocks/BeefyClientMock.sol";
import {VerificationWrapper} from "./mocks/VerificationWrapper.sol";
import {ScaleCodec} from "../src/utils/ScaleCodec.sol";
import {MerkleLibSubstrate} from "./utils/MerkleLib.sol";

library MmrLib {
    function merge(bytes32 l, bytes32 r) internal pure returns (bytes32 v) {
        assembly {
            mstore(0x00, l)
            mstore(0x20, r)
            v := keccak256(0x00, 0x40)
        }
    }

    /// Perfect-subtree root over leaves[from .. from+size).
    function peakRoot(bytes32[] memory leaves, uint256 from, uint256 size)
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
                nxt[i] = merge(lvl[2 * i], lvl[2 * i + 1]);
            }
            lvl = nxt;
        }
        return lvl[0];
    }

    /// Sibling path of leaf `idx` (relative to `from`) inside a perfect subtree of `size` leaves.
    /// Returns the siblings bottom-up and the matching order bits (1 = sibling on the left).
    function peakPath(bytes32[] memory leaves, uint256 from, uint256 size, uint256 idx)
        internal
        pure
        returns (bytes32[] memory path, uint256 order)
    {
        uint256 depth;
        {
            uint256 s = size;
            while (s > 1) {
                s /= 2;
                depth++;
            }
        }
        path = new bytes32[](depth);
        bytes32[] memory lvl = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            lvl[i] = leaves[from + i];
        }
        uint256 p = idx;
        for (uint256 d = 0; d < depth; d++) {
            if (p & 1 == 1) {
                path[d] = lvl[p - 1];
                order |= (uint256(1) << d); // sibling is on the LEFT
            } else {
                path[d] = lvl[p + 1];
            }
            bytes32[] memory nxt = new bytes32[](lvl.length / 2);
            for (uint256 i = 0; i < nxt.length; i++) {
                nxt[i] = merge(lvl[2 * i], lvl[2 * i + 1]);
            }
            lvl = nxt;
            p /= 2;
        }
    }

    /// Peak sizes of an MMR with `n` leaves, left to right (descending powers of two).
    function peakSizes(uint256 n) internal pure returns (uint256[] memory sizes) {
        uint256 count;
        for (uint256 b = 255; b + 1 > 0; b--) {
            if (n & (uint256(1) << b) != 0) count++;
            if (b == 0) break;
        }
        sizes = new uint256[](count);
        uint256 k;
        for (uint256 b = 255; b + 1 > 0; b--) {
            if (n & (uint256(1) << b) != 0) sizes[k++] = uint256(1) << b;
            if (b == 0) break;
        }
    }
}

contract ZMmrRecencyTest is Test {
    using MmrLib for bytes32;

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

    struct Mmr {
        uint256[] sizes;
        uint256[] starts;
        bytes32[] peaks;
        bytes32[] bagged; // bagged[i] = bag of peaks i..end
    }

    function _build(bytes32[] memory leaves) internal pure returns (Mmr memory m) {
        m.sizes = MmrLib.peakSizes(leaves.length);
        uint256 n = m.sizes.length;
        m.peaks = new bytes32[](n);
        m.starts = new uint256[](n);
        m.bagged = new bytes32[](n);
        uint256 off;
        for (uint256 i = 0; i < n; i++) {
            m.starts[i] = off;
            m.peaks[i] = MmrLib.peakRoot(leaves, off, m.sizes[i]);
            off += m.sizes[i];
        }
        m.bagged[n - 1] = m.peaks[n - 1];
        for (uint256 i = n - 1; i > 0; i--) {
            m.bagged[i - 1] = MmrLib.merge(m.peaks[i - 1], m.bagged[i]);
        }
    }

    function _peakOf(Mmr memory m, uint256 target) internal pure returns (uint256) {
        for (uint256 i = 0; i < m.sizes.length; i++) {
            if (target >= m.starts[i] && target < m.starts[i] + m.sizes[i]) return i;
        }
        revert("target out of range");
    }

    /// Build the MMR root over `leaves`, and the (proof, order) for leaf `target`.
    function _mmr(bytes32[] memory leaves, uint256 target)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof, uint256 order)
    {
        Mmr memory m = _build(leaves);
        root = m.bagged[0];
        uint256 pk = _peakOf(m, target);

        (bytes32[] memory inner, uint256 innerOrder) =
            MmrLib.peakPath(leaves, m.starts[pk], m.sizes[pk], target - m.starts[pk]);

        // After the inner path the accumulator equals peaks[pk]; now bag outwards:
        //   if a peak exists to the right: acc = merge(acc, bagged[pk+1])  -> order bit 0
        //   then for j = pk-1 down to 0:   acc = merge(peaks[j], acc)      -> order bit 1
        proof = new bytes32[](inner.length + (pk + 1 < m.sizes.length ? 1 : 0) + pk);
        order = innerOrder;
        for (uint256 i = 0; i < inner.length; i++) {
            proof[i] = inner[i];
        }
        uint256 w = inner.length;
        if (pk + 1 < m.sizes.length) {
            proof[w] = m.bagged[pk + 1];
            w++;
        }
        for (uint256 j = pk; j > 0; j--) {
            proof[w] = m.peaks[j - 1];
            order |= (uint256(1) << w);
            w++;
        }
    }

    function _leaf(uint256 i, bytes32 headsRoot) internal view returns (bytes32) {
        Verification.MMRLeafPartial memory p = Verification.MMRLeafPartial({
            version: 0,
            parentNumber: uint32(30_000_000 + i),
            parentHash: keccak256(abi.encodePacked("relay", i)),
            nextAuthoritySetID: 5000,
            nextAuthoritySetLen: 600,
            nextAuthoritySetRoot: keccak256("authset")
        });
        return wrapper.createMMRLeaf(p, headsRoot);
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

    // ------------------------------------------------------------------
    // The MMR model itself is sound: every leaf verifies against the root.
    // ------------------------------------------------------------------
    function test_everyLeafOfALargeMmrVerifiesAgainstTheCurrentRoot() public {
        uint256 N = 1000; // 1000 relay blocks of history: peaks 512 + 256 + 128 + 64 + 32 + 8
        bytes32[] memory leaves = new bytes32[](N);
        for (uint256 i = 0; i < N; i++) {
            leaves[i] = _leaf(i, keccak256(abi.encodePacked("headsRoot", i)));
        }
        (bytes32 root,,) = _mmr(leaves, 0);
        beefyClient.setLatestMMRRoot(root);

        uint256[8] memory probes = [uint256(0), 1, 2, 7, 511, 512, 998, 999];
        for (uint256 k = 0; k < probes.length; k++) {
            (, bytes32[] memory proof, uint256 order) = _mmr(leaves, probes[k]);
            assertTrue(
                beefyClient.verifyMMRLeafProof(leaves[probes[k]], proof, order),
                "leaf must verify against the current root"
            );
        }
    }

    // ------------------------------------------------------------------
    // The point: verifyCommitment accepts the OLDEST parachain-heads root in
    // history against the CURRENT MMR root, with no recency objection.
    // ------------------------------------------------------------------
    struct Ancient {
        bytes32 commitment;
        Verification.ParachainHeader header;
        bytes32 headsRoot;
        bytes32[] headProof;
    }

    function _ancient() internal view returns (Ancient memory a) {
        a.commitment = keccak256("a commitment from long ago");
        Verification.DigestItem[] memory d = new Verification.DigestItem[](1);
        d[0] = Verification.DigestItem({
            kind: 0,
            consensusEngineID: 0x00000000,
            data: bytes.concat(hex"01", a.commitment)
        });
        a.header = Verification.ParachainHeader({
            parentHash: keccak256("ancient-parent"),
            number: 1,
            stateRoot: keccak256("ancient-state"),
            extrinsicsRoot: keccak256("ancient-extrinsics"),
            digestItems: d
        });
        bytes32[] memory heads = new bytes32[](13);
        for (uint256 i = 0; i < 13; i++) {
            heads[i] = keccak256(abi.encodePacked("ancient-parahead:", i));
        }
        heads[1] = wrapper.createParachainHeaderMerkleLeaf(encodedBridgeHubID, a.header);
        a.headsRoot = MerkleLibSubstrate.rootFromLeaves(heads);
        a.headProof = MerkleLibSubstrate.genProof(heads, 1);
    }

    // ------------------------------------------------------------------
    // The point: verifyCommitment accepts the OLDEST parachain-heads root in
    // history against the CURRENT MMR root, with no recency objection.
    // ------------------------------------------------------------------
    function test_verifyCommitmentAcceptsTheOldestHistoricalParachainHeadsRoot() public {
        Ancient memory a = _ancient();

        // 1000 relay blocks of MMR history; the ancient block is leaf 0, everything after is newer.
        bytes32[] memory leaves = new bytes32[](1000);
        leaves[0] = _leaf(0, a.headsRoot);
        for (uint256 i = 1; i < 1000; i++) {
            leaves[i] = _leaf(i, keccak256(abi.encodePacked("headsRoot", i)));
        }
        (bytes32 root, bytes32[] memory mmrProof, uint256 mmrOrder) = _mmr(leaves, 0);

        // The light client is at the CURRENT root, 999 blocks ahead of the leaf being used.
        beefyClient.setLatestMMRRoot(root);

        assertTrue(
            Verification.verifyCommitment(
                address(beefyClient),
                encodedBridgeHubID,
                a.commitment,
                Verification.Proof({
                    header: a.header,
                    headProof: Verification.HeadProof({pos: 1, width: 13, proof: a.headProof}),
                    leafPartial: _partial(0),
                    leafProof: mmrProof,
                    leafProofOrder: mmrOrder
                }),
                true
            ),
            "a 1000-block-old parachain-heads root is accepted against the current MMR root"
        );

        emit log_named_uint("MMR leaves at verification time", 1000);
        emit log_named_uint("leaf index used", 0);
        emit log_named_uint("blocks of staleness accepted", 999);
    }
}
