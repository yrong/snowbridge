// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {InboundQueue} from "../src/InboundQueue.sol";
import {BeefyClient} from "../src/BeefyClient.sol";
import {Vault} from "../src/Vault.sol";
import {IParachainClient} from "../src/IParachainClient.sol";
import {ParaID} from "../src/Types.sol";
import {ParachainClientMock} from "./mocks/ParachainClientMock.sol";
import {IRecipient, RecipientMock} from "./mocks/RecipientMock.sol";
import {Registry} from "../src/Registry.sol";

contract InboundQueueTest is Test {
    InboundQueue public channel;
    RecipientMock public recipient;

    Vault public vault;

    event MessageDispatched(ParaID origin, uint64 nonce, InboundQueue.DispatchResult result);

    ParaID public constant ORIGIN = ParaID.wrap(1001);
    bytes32[] public proof = [bytes32(0x2f9ee6cfdf244060dc28aa46347c5219e303fc95062dd672b4e406ca5c29764b)];
    bytes public message = bytes("message");
    bytes public parachainHeaderProof = bytes("validProof");

    bytes32 constant RECIPIENT = keccak256("RecipientMock");

    function setUp() public {
        Registry registry = new Registry();
        registry.grantRole(registry.REGISTER_ROLE(), address(this));

        IParachainClient parachainClient = new ParachainClientMock(BeefyClient(address(0)), 0);
        recipient = new RecipientMock();
        registry.registerContract(RECIPIENT, address(recipient));

        vault = new Vault();

        deal(address(this), 100 ether);

        channel = new InboundQueue(registry, parachainClient, vault, 1 ether);
        vault.grantRole(vault.WITHDRAW_ROLE(), address(channel));
    }

    function testSubmit() public {
        vault.deposit{value: 50 ether}(ORIGIN);

        address relayer = makeAddr("alice");
        hoax(relayer, 1 ether);

        channel.submit(InboundQueue.Message(ORIGIN, 1, RECIPIENT, message), proof, parachainHeaderProof);

        assertEq(vault.balances(ORIGIN), 49 ether);
        assertEq(relayer.balance, 2 ether);
    }

    function testSubmitShouldFailInvalidProof() public {
        vault.deposit{value: 50 ether}(ORIGIN);

        address relayer = makeAddr("alice");
        hoax(relayer, 1 ether);

        vm.expectRevert(InboundQueue.InvalidProof.selector);
        channel.submit(InboundQueue.Message(ORIGIN, 1, RECIPIENT, message), proof, bytes("badProof"));
    }

    function testSubmitShouldFailInvalidNonce() public {
        vault.deposit{value: 50 ether}(ORIGIN);

        address relayer = makeAddr("alice");
        hoax(relayer, 1 ether);

        vm.expectRevert(InboundQueue.InvalidNonce.selector);
        channel.submit(InboundQueue.Message(ORIGIN, 2, RECIPIENT, message), proof, parachainHeaderProof);
    }

    // Test that submission fails if origin does not have sufficient funds to pay relayer
    function testSubmitShouldFailInsufficientBalance() public {
        vault.deposit{value: 0.1 ether}(ORIGIN);

        address relayer = makeAddr("alice");
        hoax(relayer, 1 ether);

        vm.expectRevert(Vault.InsufficientBalance.selector);
        channel.submit(InboundQueue.Message(ORIGIN, 1, RECIPIENT, message), proof, parachainHeaderProof);
    }

    function testSubmitShouldNotFailOnHandlerFailure() public {
        vault.deposit{value: 50 ether}(ORIGIN);

        recipient.setShouldFail();
        vm.expectEmit();
        emit MessageDispatched(ORIGIN, 1, InboundQueue.DispatchResult.Failure);

        address relayer = makeAddr("alice");
        hoax(relayer, 1 ether);

        channel.submit(InboundQueue.Message(ORIGIN, 1, RECIPIENT, message), proof, parachainHeaderProof);

        assertEq(vault.balances(ORIGIN), 49 ether);
        assertEq(relayer.balance, 2 ether);
    }

    function testSubmitShouldNotFailOnHandlerOOG() public {
        vault.deposit{value: 50 ether}(ORIGIN);

        recipient.setShouldConsumeAllGas();
        vm.expectEmit();
        emit MessageDispatched(ORIGIN, 1, InboundQueue.DispatchResult.Failure);

        address relayer = makeAddr("alice");
        hoax(relayer, 1 ether);

        channel.submit(InboundQueue.Message(ORIGIN, 1, RECIPIENT, message), proof, parachainHeaderProof);

        assertEq(vault.balances(ORIGIN), 49 ether);
        assertEq(relayer.balance, 2 ether);
    }
}
