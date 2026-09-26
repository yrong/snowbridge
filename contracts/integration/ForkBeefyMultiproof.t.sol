// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

// Fork-mainnet replay of real BEEFY submissions (see `MainnetBeefyFixture`) through the
// multiproof BeefyClient. For each, fork one block before the tx, write the local BeefyClient
// over the live code (keeping its storage: the ticket, the validator sets), re-encode the
// proofs as a multiproof and replay the call from the original relayer. For `submitFinal`, the
// live ticket is first copied into the per-relayer ticket layout. It must succeed and
// advance the MMR root.
//
// Run (needs an archive RPC; a public default is used if MAINNET_RPC_URL is unset):
//   FOUNDRY_PROFILE=integration forge test --match-contract ForkBeefyMultiproof -vv

import {BeefyClient} from "../src/BeefyClient.sol";
import {CompactProofLib} from "../test/utils/CompactProofLib.sol";
import {MainnetBeefyFixture} from "../test/MainnetSubmitFinalMultiproof.t.sol";

contract ForkBeefyMultiproofTest is MainnetBeefyFixture {
    /// Storage slot of `BeefyClient.tickets`, the same in the mainnet and the local layout.
    uint256 constant TICKETS_SLOT = 10;

    function testMainnetSubmitFinalSucceedsAfterMultiproofEtch() public {
        _replay(finalE8eb06());
    }

    function testMainnetSubmitFinal992ebbSucceedsAfterMultiproofEtch() public {
        _replay(final992ebb());
    }

    function testMainnetSubmitFiatShamirSucceedsAfterMultiproofEtch() public {
        _replay(fiatShamir0a9f5a());
    }

    function _replay(MainnetTx memory t) internal {
        // Default is a public archive endpoint; override with MAINNET_RPC_URL.
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string("https://eth.drpc.org"));
        vm.createSelectFork(rpc, t.blockNumber - 1);

        (uint128 id, uint128 len, bytes32 root,) =
            t.handover ? BeefyClient(BC).nextValidatorSet() : BeefyClient(BC).currentValidatorSet();
        assertEq(id, t.vsetId, "set id");
        assertEq(len, t.vsetLength, "set length");
        assertEq(root, t.vsetRoot, "set root");

        (bytes memory multiproofCd, BeefyClient.Commitment memory commitment) =
            _multiproofCalldata(t);

        bytes32 mmrBefore = BeefyClient(BC).latestMMRRoot();
        _etchMultiproof();
        if (!t.fiatShamir) {
            _migrateTicket(BeefyClient(BC).computeCommitmentHash(commitment));
        }
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
    /// fields. This branch keys it by relayer and adds `prevRandaoCaptured` and
    /// `commitmentHash`. Copy the live ticket into the new layout so `submitFinal` can find it.
    function _migrateTicket(bytes32 commitmentHash) internal {
        bytes32 ticketID = keccak256(abi.encode(RELAYER, commitmentHash));
        uint256 oldBase = uint256(keccak256(abi.encode(ticketID, TICKETS_SLOT)));
        uint256 newBase = uint256(keccak256(abi.encode(RELAYER, TICKETS_SLOT)));

        bytes32 packed = vm.load(BC, bytes32(oldBase));
        bytes32 prevRandao = vm.load(BC, bytes32(oldBase + 1));
        bytes32 bitfieldHash = vm.load(BC, bytes32(oldBase + 2));
        assertTrue(packed != 0, "no live ticket for the relayer");
        assertTrue(prevRandao != 0, "live ticket has no captured PREVRANDAO");

        // `prevRandaoCaptured` is packed at byte 16 of the first slot.
        vm.store(BC, bytes32(newBase), packed | bytes32(uint256(1) << 128));
        vm.store(BC, bytes32(newBase + 1), prevRandao);
        vm.store(BC, bytes32(newBase + 2), bitfieldHash);
        vm.store(BC, bytes32(newBase + 3), commitmentHash);

        // Read back through the getter to confirm the slot arithmetic.
        (uint64 blockNumber,,, bool captured, uint256 seed, bytes32 bfHash, bytes32 cHash) =
            BeefyClient(BC).tickets(RELAYER);
        assertTrue(blockNumber != 0, "ticket block number");
        assertTrue(captured, "ticket captured flag");
        assertEq(seed, uint256(prevRandao), "ticket prevRandao");
        assertEq(bfHash, bitfieldHash, "ticket bitfield hash");
        assertEq(cHash, commitmentHash, "ticket commitment hash");
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
    }
}
