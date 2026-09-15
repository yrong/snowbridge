// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Snowfork <hello@snowfork.com>
pragma solidity 0.8.34;

/// @title BLAKE2b-256 over the EIP-152 `F` compression precompile.
/// @dev Unkeyed, sequential mode, 32-byte digest — byte-identical to Substrate's `BlakeTwo256`
/// (`sp_core::hashing::blake2_256`), so a SCALE-encoded parachain header hashed here equals the
/// `parent_hash` its child header carries.
///
/// EIP-152 exposes only the compression function `F`; the parameter block, message padding, byte
/// counter and final-block flag are handled here. Cost is one `F` call (12 rounds) per 128-byte
/// block plus the calldata assembly around it.
library Blake2b {
    /// EIP-152 precompile.
    address internal constant F = address(0x09);
    /// Rounds for BLAKE2b.
    uint32 internal constant ROUNDS = 12;
    /// Block size in bytes.
    uint256 internal constant BLOCK = 128;

    /// Initial state for digest length 32, no key, fanout 1, depth 1: the BLAKE2b IV with the
    /// parameter block `0x01010020` xored into `h[0]`. Laid out as the precompile consumes it —
    /// eight little-endian u64 words.
    bytes internal constant IV_256 = hex"28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
        hex"d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b";

    error Blake2bPrecompileFailed();

    /// @notice BLAKE2b-256 of `data`.
    function hash(bytes memory data) internal view returns (bytes32 digest) {
        bytes memory h = IV_256;
        uint256 len = data.length;
        // The empty message is one all-zero block with `t = 0` and the final flag set; otherwise
        // the block holding the final byte is the final one (no extra padding block).
        uint256 blocks = len == 0 ? 1 : (len + BLOCK - 1) / BLOCK;
        for (uint256 i = 0; i < blocks; i++) {
            uint256 start = i * BLOCK;
            uint256 take = len - start < BLOCK ? len - start : BLOCK;
            h = compress(h, data, start, take, uint64(start + take), i + 1 == blocks);
        }
        assembly ("memory-safe") {
            digest := mload(add(h, 32))
        }
    }

    /// @dev One `F` call: `rounds(4, BE) ‖ h(64) ‖ m(128) ‖ t(16, LE) ‖ f(1)` → new `h(64)`. The
    /// message block is `data[start .. start + take)`, zero-padded to 128 bytes.
    function compress(
        bytes memory h,
        bytes memory data,
        uint256 start,
        uint256 take,
        uint64 t,
        bool last
    ) private view returns (bytes memory) {
        bytes memory m = new bytes(BLOCK);
        assembly ("memory-safe") {
            // Copy `take` bytes (≤ 128) in 32-byte words; the buffer is already zeroed, so mask the
            // partial tail rather than overrunning it.
            let src := add(add(data, 32), start)
            let dst := add(m, 32)
            for { let off := 0 } lt(off, take) { off := add(off, 32) } {
                let word := mload(add(src, off))
                let remaining := sub(take, off)
                if lt(remaining, 32) {
                    let keep := mul(remaining, 8)
                    word := and(word, not(sub(shl(sub(256, keep), 1), 1)))
                }
                mstore(add(dst, off), word)
            }
        }
        bytes memory input =
            abi.encodePacked(ROUNDS, h, m, le64(t), bytes8(0), last ? bytes1(0x01) : bytes1(0x00));
        (bool ok, bytes memory out) = F.staticcall(input);
        if (!ok || out.length != 64) revert Blake2bPrecompileFailed();
        return out;
    }

    /// @dev `x` as eight little-endian bytes.
    function le64(uint64 x) private pure returns (bytes8) {
        uint64 r = 0;
        for (uint256 i = 0; i < 8; i++) {
            r = (r << 8) | (x & 0xff);
            x >>= 8;
        }
        return bytes8(r);
    }
}
