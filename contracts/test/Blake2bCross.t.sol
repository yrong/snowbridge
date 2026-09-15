// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";
import {Blake2b} from "../src/utils/Blake2b.sol";

/// Cross-implementation tests for `Blake2b.hash` against three independent BLAKE2b-256
/// implementations, plus Substrate's own header hashing — the production use.
///
/// Needs `--ffi` and the oracle binary; skipped otherwise so plain `forge test` is unaffected:
///
///   BLAKE2B_ORACLE=/path/to/blake2-oracle forge test --ffi --match-contract Blake2bCrossTest
///
/// Oracles: GNU coreutils `b2sum -l 256` (C), CPython `hashlib.blake2b(digest_size=32)` (C), and
/// `sp_crypto_hashing::blake2_256` / `sp_runtime::generic::Header::hash()` (Rust, the Substrate
/// implementation itself).
contract Blake2bCrossTest is Test {
    string oracle;

    function setUp() public {
        oracle = vm.envOr("BLAKE2B_ORACLE", string(""));
    }

    modifier needsOracle() {
        if (bytes(oracle).length == 0) {
            vm.skip(true);
        }
        _;
    }

    /// Substrate's `blake2_256`, every length 0..300 and a few longer ones.
    function test_cross_substrate_blake2_256() public needsOracle {
        for (uint256 n = 0; n <= 300; n++) {
            bytes memory data = pseudoRandom(n, n + 1000);
            assertEq(
                Blake2b.hash(data), substrateHash(data), string.concat("len=", vm.toString(n))
            );
        }
        uint256[4] memory longer = [uint256(511), 512, 1023, 4096];
        for (uint256 i = 0; i < longer.length; i++) {
            bytes memory data = pseudoRandom(longer[i], longer[i]);
            assertEq(
                Blake2b.hash(data),
                substrateHash(data),
                string.concat("len=", vm.toString(longer[i]))
            );
        }
    }

    /// The production property: BLAKE2b-256 of a SCALE-encoded parachain header equals the
    /// `parent_hash` its child would carry (`Header::hash()`), for 64 synthetic headers.
    function test_cross_substrate_header_hash() public needsOracle {
        for (uint256 seed = 0; seed < 64; seed++) {
            (bytes memory encoded, bytes32 expected) = substrateHeader(seed);
            assertGt(encoded.length, 128, "header should span more than one block");
            assertEq(Blake2b.hash(encoded), expected, string.concat("seed=", vm.toString(seed)));
        }
    }

    /// CPython's hashlib (its own C implementation), a spread of lengths.
    function test_cross_python_hashlib() public needsOracle {
        uint256[12] memory lens = [uint256(0), 1, 31, 32, 63, 64, 127, 128, 129, 255, 256, 300];
        for (uint256 i = 0; i < lens.length; i++) {
            bytes memory data = pseudoRandom(lens[i], lens[i] + 2000);
            assertEq(
                Blake2b.hash(data), pythonHash(data), string.concat("len=", vm.toString(lens[i]))
            );
        }
    }

    /// GNU coreutils `b2sum -l 256` (C), a spread of lengths.
    function test_cross_b2sum() public needsOracle {
        uint256[12] memory lens = [uint256(0), 1, 31, 32, 63, 64, 127, 128, 129, 255, 256, 300];
        for (uint256 i = 0; i < lens.length; i++) {
            bytes memory data = pseudoRandom(lens[i], lens[i] + 3000);
            assertEq(
                Blake2b.hash(data), b2sumHash(data), string.concat("len=", vm.toString(lens[i]))
            );
        }
    }

    // ---- oracles ----

    function substrateHash(bytes memory data) internal returns (bytes32) {
        string[] memory cmd = new string[](3);
        cmd[0] = oracle;
        cmd[1] = "hash";
        cmd[2] = toHex(data);
        return bytes32(vm.ffi(cmd));
    }

    function substrateHeader(uint256 seed) internal returns (bytes memory encoded, bytes32 hash) {
        string[] memory cmd = new string[](3);
        cmd[0] = oracle;
        cmd[1] = "header";
        cmd[2] = vm.toString(seed);
        string[] memory parts = vm.split(string(vm.ffi(cmd)), " ");
        encoded = vm.parseBytes(string.concat("0x", parts[0]));
        hash = vm.parseBytes32(string.concat("0x", parts[1]));
    }

    function pythonHash(bytes memory data) internal returns (bytes32) {
        string[] memory cmd = new string[](3);
        cmd[0] = "python3";
        cmd[1] = "-c";
        cmd[2] = string.concat(
            "import hashlib;print(hashlib.blake2b(bytes.fromhex('",
            toHex(data),
            "'),digest_size=32).hexdigest())"
        );
        return bytes32(vm.ffi(cmd));
    }

    function b2sumHash(bytes memory data) internal returns (bytes32) {
        string memory path = "test/data/blake2b-cross.bin";
        vm.writeFileBinary(path, data);
        string[] memory cmd = new string[](4);
        cmd[0] = "b2sum";
        cmd[1] = "-l";
        cmd[2] = "256";
        cmd[3] = path;
        // Output is "<hex>  <path>", which is not pure hex, so ffi returns it as text.
        string[] memory parts = vm.split(string(vm.ffi(cmd)), " ");
        return vm.parseBytes32(string.concat("0x", parts[0]));
    }

    // ---- helpers ----

    function pseudoRandom(uint256 n, uint256 seed) internal pure returns (bytes memory out) {
        out = new bytes(n);
        bytes32 acc = keccak256(abi.encode(seed));
        for (uint256 i = 0; i < n; i++) {
            if (i % 32 == 0) acc = keccak256(abi.encode(acc, i));
            out[i] = acc[i % 32];
        }
    }

    function toHex(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}
