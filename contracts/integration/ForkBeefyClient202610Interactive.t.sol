// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {BeefyClient} from "../src/BeefyClient.sol";
import {ForkBeefyClient202610Base} from "./ForkBeefyClient202610Base.sol";

/// @notice The mainnet submitInitial / commitPrevRandao / submitFinal sequence for relay block
///         33,599,510, replayed against the new BeefyClient with the same commitment, MMR leaf
///         and PREVRANDAO. The relayer's bitfield claims 50 signers that the block's stored
///         justification lacks, so full submissions claim the stored signers instead.
contract ForkBeefyClient202610InteractiveTest is ForkBeefyClient202610Base {
    // Block of submitFinal tx 0xc02ad755…, so the production ticket still holds the captured
    // PREVRANDAO.
    uint256 private constant SUBMIT_FINAL_BLOCK = 26_276_737;

    struct Replay {
        BeefyClient.Commitment commitment;
        uint256[] bitfield;
        BeefyClient.ValidatorProof initialProof;
        FinalArgs original;
        BeefyClient.ValidatorProof[] signers;
        uint256[] signersBitfield;
        bytes32 commitmentHash;
    }

    BeefyClient private client;
    uint256 private prevRandao;
    uint256 private randaoDelay;

    function setUp() public {
        forkAt(SUBMIT_FINAL_BLOCK);
        client = deployCheckpointedClient();

        Replay memory r = load();
        (uint64 ticketBlock,, uint32 required, uint256 randao,) =
            BeefyClient(OLD_BEEFY_CLIENT).tickets(ticketID(RELAYER, r.commitmentHash));
        assertEq(required, 28);
        assertGt(randao, 0);
        prevRandao = randao;
        // commitPrevRandao landed one block before submitFinal.
        randaoDelay = block.number - 1 - ticketBlock;
        assertGe(randaoDelay, RANDAO_COMMIT_DELAY);
        assertLe(randaoDelay, RANDAO_COMMIT_DELAY + RANDAO_COMMIT_EXPIRATION);
    }

    function load() private view returns (Replay memory r) {
        (r.commitment, r.bitfield, r.initialProof) = abi.decode(
            readFixture("tx-int-submitInitial.hex"),
            (BeefyClient.Commitment, uint256[], BeefyClient.ValidatorProof)
        );
        r.original = decodeFinalArgs(readFixture("tx-int-submitFinal.hex"));
        r.signers = decodeFinalArgs(readFixture("beefy-33599510-all-signers.hex")).proofs;
        r.signersBitfield = new uint256[](r.bitfield.length);
        for (uint256 i = 0; i < r.signers.length; i++) {
            r.signersBitfield[r.signers[i].index / 256] |= 1 << (r.signers[i].index % 256);
        }
        r.commitmentHash = client.computeCommitmentHash(r.commitment);
        assertEq(r.original.proofs.length, 28);
        assertEq(r.signers.length, 401);
    }

    function submitInitialAs(
        Replay memory r,
        address relayer,
        uint256[] memory bitfield,
        BeefyClient.ValidatorProof memory proof
    ) private returns (uint32 required) {
        vm.prank(relayer);
        client.submitInitial(r.commitment, bitfield, proof);
        (,, required,,) = client.tickets(ticketID(relayer, r.commitmentHash));
    }

    function captureRandao(Replay memory r, address relayer) private {
        vm.prevrandao(bytes32(prevRandao));
        vm.prank(relayer);
        client.commitPrevRandao(r.commitmentHash);
    }

    function finalBitfieldOf(Replay memory r, address relayer, uint256[] memory bitfield)
        private
        returns (uint256[] memory finalBitfield)
    {
        vm.prank(relayer);
        finalBitfield = client.createFinalBitfield(r.commitmentHash, bitfield);
    }

    function submitFinalAs(
        Replay memory r,
        address relayer,
        uint256[] memory bitfield,
        BeefyClient.ValidatorProof[] memory proofs
    ) private {
        vm.prank(relayer);
        client.submitFinal(
            r.commitment,
            bitfield,
            proofs,
            r.original.leaf,
            r.original.leafProof,
            r.original.leafProofOrder
        );
    }

    /// @dev Submits the stored signers' bitfield and proves the sample with their signatures.
    function finishWithStoredSigners(Replay memory r, address relayer, uint256 required) private {
        BeefyClient.ValidatorProof[] memory proofs =
            selectProofs(r.signers, finalBitfieldOf(r, relayer, r.signersBitfield));
        assertEq(proofs.length, required);

        uint256 gasBefore = gasleft();
        submitFinalAs(r, relayer, r.signersBitfield, proofs);
        emit log_named_uint(
            string.concat("submitFinal gas (", vm.toString(required), " proofs)"),
            gasBefore - gasleft()
        );
        assertEq(client.latestBeefyBlock(), r.commitment.blockNumber);
    }

    /// The new minimum gives 20 + log2(600) + 1 = 31 signatures.
    function testSubmitFinalNeeds31Signatures() public {
        Replay memory r = load();
        address stored = makeAddr("stored-signers-relayer");
        BeefyClient.ValidatorProof memory other =
            r.signers[r.signers[0].index == r.initialProof.index ? 1 : 0];

        assertEq(submitInitialAs(r, RELAYER, r.bitfield, r.initialProof), 31);
        assertEq(submitInitialAs(r, stored, r.signersBitfield, other), 31);
        vm.roll(block.number + randaoDelay);
        captureRandao(r, RELAYER);
        captureRandao(r, stored);

        // Same seed and bitfield as mainnet, so the original 28 proofs are the first picks.
        uint256[] memory finalBitfield = finalBitfieldOf(r, RELAYER, r.bitfield);
        assertEq(countSet(finalBitfield), 31);
        assertEq(selectProofs(r.original.proofs, finalBitfield).length, 28);
        vm.expectRevert(BeefyClient.InvalidValidatorProofLength.selector);
        submitFinalAs(r, RELAYER, r.bitfield, r.original.proofs);

        finishWithStoredSigners(r, stored, 31);
    }
}
