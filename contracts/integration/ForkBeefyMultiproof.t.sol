// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

// Fork-mainnet checks of real BEEFY submissions (see `MainnetBeefyFixture`) against the local
// BeefyClient. For each, fork one block before the tx and write the local BeefyClient over the
// live code (keeping its storage: the ticket, the validator sets).
//
// - `submitFiatShamir` is replayed from the original relayer with the proofs re-encoded as a
//   multiproof. It must succeed and advance the MMR root.
// - For `submitFinal`, the live ticket is copied into the per-relayer two-slot layout and must
//   sample from the claimed bitfield (see `_checkMigratedTicketSamples` for why the historical
//   proofs are not replayed here).
//
// Run (needs an archive RPC; a public default is used if MAINNET_RPC_URL is unset):
//   FOUNDRY_PROFILE=integration forge test --match-contract ForkBeefyMultiproof -vv

import {BeefyClient} from "../src/BeefyClient.sol";
import {Bitfield} from "../src/utils/Bitfield.sol";
import {CompactProofLib} from "../test/utils/CompactProofLib.sol";
import {MainnetBeefyFixture} from "../test/MainnetSubmitFinalMultiproof.t.sol";

contract ForkBeefyMultiproofTest is MainnetBeefyFixture {
    /// Storage slot of `BeefyClient.tickets` on mainnet and in the local layout.
    uint256 constant LIVE_TICKETS_SLOT = 10;
    uint256 constant TICKETS_SLOT = 6;

    function testMainnetTicketE8eb06MigratesAndSamples() public {
        _checkTicket(finalE8eb06());
    }

    function testMainnetTicket992ebbMigratesAndSamples() public {
        _checkTicket(final992ebb());
    }

    function testMainnetSubmitFiatShamirSucceedsAfterMultiproofEtch() public {
        _replay(fiatShamir0a9f5a());
    }

    function _fork(MainnetTx memory t) internal {
        // Default is a public archive endpoint; override with MAINNET_RPC_URL.
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string("https://eth.drpc.org"));
        vm.createSelectFork(rpc, t.blockNumber - 1);

        (uint128 id, uint128 len, bytes32 root) =
            t.handover ? BeefyClient(BC).nextValidatorSet() : BeefyClient(BC).currentValidatorSet();
        assertEq(id, t.vsetId, "set id");
        assertEq(len, t.vsetLength, "set length");
        assertEq(root, t.vsetRoot, "set root");
    }

    function _checkTicket(MainnetTx memory t) internal {
        _fork(t);
        BeefyClient.Commitment memory commitment;
        uint256[] memory bitfield;
        (commitment, bitfield,,,,) = _load(t);

        _etchMultiproof();
        bytes32 commitmentHash = BeefyClient(BC).computeCommitmentHash(commitment);
        _migrateTicket(commitmentHash);
        vm.roll(t.blockNumber);
        _checkMigratedTicketSamples(commitmentHash, bitfield);
    }

    function _replay(MainnetTx memory t) internal {
        _fork(t);
        (bytes memory multiproofCd, BeefyClient.Commitment memory commitment) =
            _multiproofCalldata(t);

        bytes32 mmrBefore = BeefyClient(BC).latestMMRRoot();
        _etchMultiproof();
        vm.roll(t.blockNumber);
        vm.prank(RELAYER);
        (bool ok, bytes memory ret) = BC.call(multiproofCd);
        assertTrue(ok, string.concat(t.name, " reverted: ", vm.toString(ret)));

        assertEq(BeefyClient(BC).latestBeefyBlock(), commitment.blockNumber, "beefy block");
        assertTrue(BeefyClient(BC).latestMMRRoot() != mmrBefore, "MMR root must advance");
    }

    /// The fixture's call with the proofs re-encoded as a multiproof.
    function _multiproofCalldata(MainnetTx memory t)
        internal
        view
        returns (bytes memory cd, BeefyClient.Commitment memory commitment)
    {
        uint256[] memory bitfield;
        BeefyClient.ValidatorProof[] memory proofs;
        BeefyClient.MMRLeaf memory leaf;
        bytes32[] memory leafProof;
        uint256 leafProofOrder;
        (commitment, bitfield, proofs, leaf, leafProof, leafProofOrder) = _load(t);
        cd = abi.encodeWithSelector(
            t.fiatShamir
                ? BeefyClient.submitFiatShamir.selector
                : BeefyClient.submitFinal.selector,
            commitment,
            bitfield,
            CompactProofLib.toCompact(proofs, t.vsetLength),
            leaf,
            leafProof,
            leafProofOrder
        );
    }

    /// Mainnet stores the relayer's ticket under `keccak(relayer, commitmentHash)` with three
    /// fields. This branch keys it by relayer and packs it into two slots. Copy the live ticket
    /// into the new layout.
    function _migrateTicket(bytes32 commitmentHash) internal {
        bytes32 ticketID = keccak256(abi.encode(RELAYER, commitmentHash));
        uint256 oldBase = uint256(keccak256(abi.encode(ticketID, LIVE_TICKETS_SLOT)));
        uint256 newBase = uint256(keccak256(abi.encode(RELAYER, TICKETS_SLOT)));

        bytes32 packed = vm.load(BC, bytes32(oldBase));
        bytes32 prevRandao = vm.load(BC, bytes32(oldBase + 1));
        bytes32 bitfieldHash = vm.load(BC, bytes32(oldBase + 2));
        assertTrue(packed != 0, "no live ticket for the relayer");
        assertTrue(prevRandao != 0, "live ticket has no captured PREVRANDAO");

        // Slot 0 keeps blockNumber / validatorSetLen / numRequiredSignatures in its low 128 bits
        // and takes the 128-bit seed above them. Slot 1 is the claim hash.
        uint256 seed = uint256(uint128(uint256(prevRandao)));
        if (seed == 0) {
            seed = 1;
        }
        bytes32 claim = keccak256(abi.encode(commitmentHash, bitfieldHash));
        vm.store(BC, bytes32(newBase), bytes32(uint256(packed) | (seed << 128)));
        vm.store(BC, bytes32(newBase + 1), claim);

        (uint64 blockNumber,,, uint128 stored, bytes32 storedClaim) =
            BeefyClient(BC).tickets(RELAYER);
        assertTrue(blockNumber != 0, "ticket block number");
        assertEq(stored, seed, "ticket seed");
        assertEq(storedClaim, claim, "ticket claim");
    }

    /// The migrated ticket is open, captured and bound to this commitment and bitfield:
    /// `createFinalBitfield` accepts it and samples `numRequiredSignatures` validators from the
    /// claimed bitfield. The historical `submitFinal` proofs cannot be replayed: they answer the
    /// sample drawn from the full 256-bit PREVRANDAO, while this client samples from its low
    /// 128 bits. The multiproof itself is replayed on real data in #1813.
    function _checkMigratedTicketSamples(bytes32 commitmentHash, uint256[] memory bf) internal {
        (,, uint32 required,,) = BeefyClient(BC).tickets(RELAYER);
        vm.prank(RELAYER);
        uint256[] memory sample = BeefyClient(BC).createFinalBitfield(commitmentHash, bf);
        assertEq(Bitfield.countSetBits(sample), required, "sample size");
        for (uint256 w = 0; w < sample.length; w++) {
            assertEq(sample[w] & ~bf[w], 0, "sample outside the claimed bitfield");
        }
    }

    function _etchMultiproof() internal {
        BeefyClient live = BeefyClient(BC);
        BeefyClient.ValidatorSet memory d0 =
            BeefyClient.ValidatorSet({id: 0, length: 1, root: bytes32(0)});
        BeefyClient.ValidatorSet memory d1 =
            BeefyClient.ValidatorSet({id: 1, length: 1, root: bytes32(0)});
        // Immutables live in the code, so rebuild it with the live values.
        BeefyClient patched = new BeefyClient(
            live.randaoCommitDelay(),
            live.randaoCommitExpiration(),
            live.minNumRequiredSignatures(),
            live.fiatShamirRequiredSignatures(),
            0,
            d0,
            d1
        );
        vm.etch(BC, address(patched).code);
        // The local ValidatorSetState is two slots (usage counters moved out), so the next set
        // moves from slots 6-7 to 4-5. The current set stays at 2-3.
        vm.store(BC, bytes32(uint256(4)), vm.load(BC, bytes32(uint256(6))));
        vm.store(BC, bytes32(uint256(5)), vm.load(BC, bytes32(uint256(7))));
    }
}
