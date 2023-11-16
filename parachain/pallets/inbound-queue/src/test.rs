// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
use super::*;

use frame_support::{assert_noop, assert_ok};
use hex_literal::hex;
use snowbridge_core::inbound::Proof;
use sp_keyring::AccountKeyring as Keyring;
use sp_runtime::{DispatchError, TokenError};
use sp_std::convert::From;

use crate::{fixtures::make_create_message, Event as InboundQueueEvent};

use crate::mock::{
	expect_events, mock_event_log, mock_event_log_invalid_channel, mock_event_log_invalid_gateway,
	new_tester, AccountId, Balances, InboundQueue, RuntimeOrigin, Test, ASSET_HUB_PARAID,
};

#[test]
fn test_submit_happy_path() {
	new_tester().execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Submit message
		let message = make_create_message().message;
		assert_ok!(InboundQueue::submit(origin.clone(), message.clone()));
		expect_events(vec![InboundQueueEvent::MessageReceived {
			channel_id: hex!("c173fac324158e77fb5840738a1a541f633cbec8884c6a601c567d2b376a0539")
				.into(),
			nonce: 1,
			message_id: [
				168, 12, 232, 40, 69, 197, 207, 74, 203, 65, 199, 240, 164, 52, 244, 217, 62, 156,
				107, 237, 117, 203, 233, 78, 251, 233, 31, 54, 155, 124, 204, 201,
			],
		}
		.into()]);
	});
}

#[test]
fn test_submit_xcm_invalid_channel() {
	new_tester().execute_with(|| {
		let log = mock_event_log_invalid_channel();
		let envelope = InboundQueue::decode(log).unwrap();
		let err = InboundQueue::validate(&envelope).unwrap_err();
		assert_eq!(err, Error::<Test>::InvalidChannel);
	});
}

#[test]
fn test_submit_with_invalid_gateway() {
	new_tester().execute_with(|| {
		let log = mock_event_log_invalid_gateway();
		let envelope = InboundQueue::decode(log).unwrap();
		let err = InboundQueue::validate(&envelope).unwrap_err();
		assert_eq!(err, Error::<Test>::InvalidGateway);
	});
}

#[test]
fn test_submit_with_invalid_nonce() {
	new_tester().execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Submit message
		let message = make_create_message().message;
		assert_ok!(InboundQueue::submit(origin.clone(), message.clone()));

		let nonce: u64 = <Nonce<Test>>::get(ChannelId::from(hex!(
			"c173fac324158e77fb5840738a1a541f633cbec8884c6a601c567d2b376a0539"
		)));
		assert_eq!(nonce, 1);

		// Submit the same again
		assert_noop!(
			InboundQueue::submit(origin.clone(), message.clone()),
			Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn test_submit_no_funds_to_reward_relayers() {
	new_tester().execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Reset balance of sovereign_account to zero so to trigger the FundsUnavailable error
		let sovereign_account = sibling_sovereign_account::<Test>(ASSET_HUB_PARAID.into());
		Balances::set_balance(&sovereign_account, 0);

		// Submit message
		let message = make_create_message().message;
		assert_noop!(
			InboundQueue::submit(origin.clone(), message.clone()),
			TokenError::FundsUnavailable
		);
	});
}

#[test]
fn test_set_operating_mode() {
	new_tester().execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);
		let message = Message {
			event_log: mock_event_log(),
			proof: Proof {
				block_hash: Default::default(),
				tx_index: Default::default(),
				data: Default::default(),
			},
		};

		assert_ok!(InboundQueue::set_operating_mode(
			RuntimeOrigin::root(),
			snowbridge_core::BasicOperatingMode::Halted
		));

		assert_noop!(InboundQueue::submit(origin, message), Error::<Test>::Halted);
	});
}

#[test]
fn test_set_operating_mode_root_only() {
	new_tester().execute_with(|| {
		assert_noop!(
			InboundQueue::set_operating_mode(
				RuntimeOrigin::signed(Keyring::Bob.into()),
				snowbridge_core::BasicOperatingMode::Halted
			),
			DispatchError::BadOrigin
		);
	});
}
