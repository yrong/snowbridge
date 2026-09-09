// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

/// @dev Test helper for building the `Ticket.sigRoot` / Fiat-Shamir signature-commitment tree
/// (SNOWBSC-689 fix) verified on-chain via OpenZeppelin's `MerkleProof`. Deliberately NOT the
/// Substrate promote-lone-node scheme used elsewhere in these tests: OZ's verifier has no
/// position/width awareness, so a non-uniform-depth tree here would reopen the exact aliasing
/// class the fix exists to close. Every real leaf gets the same proof length by padding the
/// leaf set up to the next power of two before building.
library SigTreeLib {
    function sigLeaf(uint256 index, uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(index, v, r, s))));
    }

    function hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /// @return root the tree root (sigRoot)
    /// @return proofs proofs[i] is the sibling path for leaves[i], in the same order
    function buildTree(bytes32[] memory leaves)
        internal
        pure
        returns (bytes32 root, bytes32[][] memory proofs)
    {
        uint256 n = leaves.length;
        require(n > 0, "SigTreeLib: no leaves");

        uint256 padded = 1;
        while (padded < n) {
            padded *= 2;
        }

        bytes32[] memory level = new bytes32[](padded);
        for (uint256 i = 0; i < n; i++) {
            level[i] = leaves[i];
        }
        for (uint256 i = n; i < padded; i++) {
            level[i] = leaves[n - 1];
        }

        uint256 depthCount = 0;
        {
            uint256 p = padded;
            while (p > 1) {
                p /= 2;
                depthCount++;
            }
        }

        proofs = new bytes32[][](n);
        for (uint256 i = 0; i < n; i++) {
            proofs[i] = new bytes32[](depthCount);
        }

        uint256[] memory positions = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            positions[i] = i;
        }

        uint256 width = padded;
        for (uint256 lvl = 0; lvl < depthCount; lvl++) {
            for (uint256 i = 0; i < n; i++) {
                proofs[i][lvl] = level[positions[i] ^ 1];
            }
            bytes32[] memory nextLevel = new bytes32[](width / 2);
            for (uint256 j = 0; j < width; j += 2) {
                nextLevel[j / 2] = hashPair(level[j], level[j + 1]);
            }
            for (uint256 i = 0; i < n; i++) {
                positions[i] = positions[i] / 2;
            }
            level = nextLevel;
            width = width / 2;
        }
        root = level[0];
    }
}
