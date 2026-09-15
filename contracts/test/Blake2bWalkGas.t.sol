// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test, console} from "forge-std/Test.sol";
import {Verification} from "../src/Verification.sol";
import {ScaleCodec} from "../src/utils/ScaleCodec.sol";
import {Blake2b} from "../src/utils/Blake2b.sol";

/// The ancestor walk from the `Verification.sol` integration sketch, in isolation, so its marginal
/// cost per hop can be measured on a real BridgeHub header (block 866,538, three digest items).
contract WalkHarness {
    error BrokenChain(uint256 hop);

    function walk(bytes32 parentHash, Verification.ParachainHeader[] calldata ancestors)
        external
        view
        returns (bytes32)
    {
        bytes32 expected = parentHash;
        for (uint256 i = 0; i < ancestors.length; i++) {
            if (Blake2b.hash(encodeHeader(ancestors[i])) != expected) revert BrokenChain(i);
            expected = ancestors[i].parentHash;
        }
        return expected;
    }

    /// `createParachainHeader` without the `encodedParaID ++ compact(len)` prefix: `parent_hash`
    /// is over the bare SCALE header.
    function encodeHeader(Verification.ParachainHeader calldata header)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            header.parentHash,
            ScaleCodec.checkedEncodeCompactU32(header.number),
            header.stateRoot,
            header.extrinsicsRoot,
            Verification.encodeDigestItems(header.digestItems)
        );
    }
}

contract Blake2bWalkGasTest is Test {
    WalkHarness h;

    function setUp() public {
        h = new WalkHarness();
    }

    /// A chain of `n` headers, each carrying the BLAKE2b-256 of its parent so the walk verifies.
    function chain(uint256 n)
        internal
        view
        returns (bytes32 tip, Verification.ParachainHeader[] memory ancestors)
    {
        ancestors = new Verification.ParachainHeader[](n);
        bytes32 link = 0x1df01d40273b074708115135fd7f76801ad4e4f1266a771a037962ee3a03259d;
        // Build oldest-first so each header can embed its parent's hash, then reverse into the
        // newest-first order the walk consumes.
        Verification.ParachainHeader[] memory oldestFirst = new Verification.ParachainHeader[](n);
        for (uint256 i = 0; i < n; i++) {
            oldestFirst[i] = realHeader(866_538 + i, link);
            link = Blake2b.hash(encodeMem(oldestFirst[i]));
        }
        tip = link;
        for (uint256 i = 0; i < n; i++) {
            ancestors[i] = oldestFirst[n - 1 - i];
        }
    }

    function test_walk_gas_0_1_3_hops() public {
        uint256[3] memory hops = [uint256(0), 1, 3];
        uint256 base;
        for (uint256 k = 0; k < hops.length; k++) {
            (bytes32 tip, Verification.ParachainHeader[] memory ancestors) = chain(hops[k]);
            uint256 before = gasleft();
            h.walk(tip, ancestors);
            uint256 exec = before - gasleft();
            if (k == 0) base = exec;

            // Intrinsic calldata gas for the ancestors argument, EIP-2028 pricing.
            bytes memory cd = abi.encode(ancestors);
            uint256 calldataGas;
            for (uint256 i = 0; i < cd.length; i++) {
                calldataGas += cd[i] == 0 ? 4 : 16;
            }
            console.log("hops", hops[k]);
            console.log("  execution gas (walk call)      ", exec);
            console.log("  marginal execution over 0 hops ", exec - base);
            console.log("  ancestors ABI bytes            ", cd.length);
            console.log("  intrinsic calldata gas         ", calldataGas);
            console.log("  marginal total (exec + calldata)", exec - base + calldataGas);
        }
    }

    // ---- fixture: the Verification.t.sol header, re-parented ----

    function realHeader(uint256 number, bytes32 parentHash)
        internal
        pure
        returns (Verification.ParachainHeader memory)
    {
        Verification.DigestItem[] memory digestItems = new Verification.DigestItem[](3);
        digestItems[0] = Verification.DigestItem({
            kind: 6, consensusEngineID: 0x61757261, data: hex"c1f05e0800000000"
        });
        digestItems[1] = Verification.DigestItem({
            kind: 4,
            consensusEngineID: 0x52505352,
            data: hex"73a902d5a4fa8fea942d01ad3c1dc32b51192c3a98c39fcc59299006ed391a5e2e005501"
        });
        digestItems[2] = Verification.DigestItem({
            kind: 5,
            consensusEngineID: 0x61757261,
            data: hex"fcfbfaf1ad15d24cb4980436c18aec6211e2255f648df0e05e73a7858fba8c31726925f1a825383d0d3cb590502b18978101a6391fbeef5ab53e14c05124188c"
        });
        return Verification.ParachainHeader({
            parentHash: parentHash,
            number: number,
            stateRoot: 0x7b2d59d4de7c629b55a9bc9b76d932616f2011a26f09b52da36e070d6a7eee0d,
            extrinsicsRoot: 0x9d1c5d256003f68dda03dc33810a88a61f73791dc7ff92b04232a6b1b4f4b3c0,
            digestItems: digestItems
        });
    }

    function encodeMem(Verification.ParachainHeader memory header)
        internal
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(
            header.parentHash,
            ScaleCodec.checkedEncodeCompactU32(header.number),
            header.stateRoot,
            header.extrinsicsRoot
        );
        out = bytes.concat(
            out, ScaleCodec.checkedEncodeCompactU32(uint32(header.digestItems.length))
        );
        for (uint256 i = 0; i < header.digestItems.length; i++) {
            Verification.DigestItem memory item = header.digestItems[i];
            out = bytes.concat(out, bytes1(uint8(item.kind)));
            if (item.kind == 4 || item.kind == 5 || item.kind == 6) {
                out = bytes.concat(out, item.consensusEngineID);
            }
            out = bytes.concat(
                out, ScaleCodec.checkedEncodeCompactU32(uint32(item.data.length)), item.data
            );
        }
    }
}
