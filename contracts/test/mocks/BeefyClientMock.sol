// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {BeefyClient} from "../../src/BeefyClient.sol";

contract BeefyClientMock is BeefyClient {
    constructor(
        uint256 _randaoCommitDelay,
        uint256 _randaoCommitExpiration,
        uint256 _minNumRequiredSignatures,
        uint256 _fiatShamirRequiredSignatures,
        uint64 _initialBeefyBlock,
        ValidatorSet memory _initialValidatorSet,
        ValidatorSet memory _nextValidatorSet
    )
        BeefyClient(
            _randaoCommitDelay,
            _randaoCommitExpiration,
            _minNumRequiredSignatures,
            _fiatShamirRequiredSignatures,
            _initialBeefyBlock,
            _initialValidatorSet,
            _nextValidatorSet
        )
    {}

    function encodeCommitment_public(Commitment calldata commitment)
        external
        pure
        returns (bytes memory)
    {
        return encodeCommitment(commitment);
    }

    function setTicketValidatorSetLen(bytes32, uint32 validatorSetLen) external {
        tickets[msg.sender].validatorSetLen = validatorSetLen;
    }

    function setLatestBeefyBlock(uint32 _latestBeefyBlock) external {
        latestBeefyBlock = _latestBeefyBlock;
    }

    function setLatestMMRRoot(bytes32 _latestMMRRoot) external {
        latestMMRRoot = _latestMMRRoot;
    }

    function initialize_public(
        uint64 _initialBeefyBlock,
        ValidatorSet calldata _initialValidatorSet,
        ValidatorSet calldata _nextValidatorSet
    ) external {
        latestBeefyBlock = _initialBeefyBlock;
        currentSetIndex = 0;
        validatorSets[0] = ValidatorSetState(
            _initialValidatorSet.id, _initialValidatorSet.length, _initialValidatorSet.root
        );
        validatorSets[1] = ValidatorSetState(
            _nextValidatorSet.id, _nextValidatorSet.length, _nextValidatorSet.root
        );
    }

    function getValidatorCounter(bool next, uint256 index) public view returns (uint16) {
        uint8 current = currentSetIndex;
        return usageCounters[validatorSets[next ? current ^ 1 : current].root].get(index);
    }

    function computeNumRequiredSignatures_public(
        uint256 validatorSetLen,
        uint256 signatureUsageCount,
        uint256 minSignatures
    ) public pure returns (uint256) {
        return computeNumRequiredSignatures(validatorSetLen, signatureUsageCount, minSignatures);
    }

    function computeQuorum_public(uint256 numValidators) public pure returns (uint256) {
        return computeQuorum(numValidators);
    }

    function computeMaxRequiredSignatures_public(uint256 numValidators)
        public
        pure
        returns (uint256)
    {
        return computeMaxRequiredSignatures(numValidators);
    }

    /// @dev Leave the caller with a closed ticket whose slots are all non-zero, as after an
    /// earlier submission. Used to measure the cost of reusing ticket storage.
    function seedClosedTicket() external {
        tickets[msg.sender] = Ticket({
            blockNumber: 0,
            validatorSetLen: 1,
            numRequiredSignatures: 1,
            seed: 1,
            claimHash: bytes32(uint256(1))
        });
    }

    function getTicket(bytes32) public view returns (Ticket memory) {
        return tickets[msg.sender];
    }
}
