// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {BeefyClient} from "../src/BeefyClient.sol";
import {BeefyClientTest} from "./BeefyClient.t.sol";
import {CompactProofLib} from "./utils/CompactProofLib.sol";

/// @dev Gas of each kind of BEEFY update: two-phase and Fiat-Shamir, same set and handover.
/// Slots that are always non-zero on mainnet (latestBeefyBlock, latestMMRRoot and the relayer's
/// ticket) are made non-zero first. Same-set updates send an empty MMR leaf.
///
/// Run one test at a time, or the gas report also counts the inherited BeefyClientTest tests:
/// FOUNDRY_PROFILE=production FOUNDRY_ISOLATE=true forge test \
///     --match-contract '^BeefyClientUpdateGasTest$' \
///     --match-test '^testGasInteractiveSameSet\(\)$' --hardfork amsterdam --gas-report
contract BeefyClientUpdateGasTest is BeefyClientTest {
    function warm(uint32 id) internal returns (BeefyClient.Commitment memory c) {
        c = initialize(id);
        beefyClient.setLatestBeefyBlock(1);
        beefyClient.setLatestMMRRoot(bytes32(uint256(1)));
        beefyClient.seedClosedTicket();
    }

    function interactive(uint32 id, bool handover) internal {
        BeefyClient.Commitment memory c = warm(id);
        beefyClient.submitInitial(c, bitfield, finalValidatorProofs[0]);
        vm.roll(block.number + randaoCommitDelay);
        commitPrevRandao();
        createFinalProofs();
        if (handover) {
            beefyClient.submitFinal(
                c,
                bitfield,
                CompactProofLib.toCompact(finalValidatorProofs, setSize),
                mmrLeaf,
                mmrLeafProofs,
                leafProofOrder
            );
        } else {
            beefyClient.submitFinal(
                c,
                bitfield,
                CompactProofLib.toCompact(finalValidatorProofs, setSize),
                emptyLeaf,
                emptyLeafProofs,
                emptyLeafProofOrder
            );
        }
    }

    function fs(uint32 id, bool handover) internal {
        BeefyClient.Commitment memory c = warm(id);
        if (handover) {
            beefyClient.submitFiatShamir(
                c,
                bitfield,
                CompactProofLib.toCompact(fiatShamirValidatorProofs, setSize),
                mmrLeaf,
                mmrLeafProofs,
                leafProofOrder
            );
        } else {
            beefyClient.submitFiatShamir(
                c,
                bitfield,
                CompactProofLib.toCompact(fiatShamirValidatorProofs, setSize),
                emptyLeaf,
                emptyLeafProofs,
                emptyLeafProofOrder
            );
        }
    }

    function testGasInteractiveSameSet() public {
        interactive(setId, false);
    }

    function testGasInteractiveHandover() public {
        interactive(setId - 1, true);
    }

    function testGasFiatShamirSameSet() public {
        fs(setId, false);
    }

    function testGasFiatShamirHandover() public {
        fs(setId - 1, true);
    }
}
