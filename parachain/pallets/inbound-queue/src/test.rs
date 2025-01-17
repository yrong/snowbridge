// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
use super::*;

use frame_support::{
	assert_noop, assert_ok,
	dispatch::DispatchError,
	parameter_types,
	traits::{ConstU64, Everything, GenesisBuild},
};
use sp_core::{ConstU32, H160, H256};
use sp_keyring::AccountKeyring as Keyring;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
	ArithmeticError, MultiSignature,
};
use sp_std::convert::From;

use snowbridge_core::{Message, Proof};
use snowbridge_ethereum::Log;

use hex_literal::hex;

use crate::{self as inbound_queue, envelope::Envelope, Error, Event as InboundQueueEvent};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		InboundQueue: inbound_queue::{Pallet, Call, Storage, Event<T>},
	}
);

pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}

impl frame_system::Config for Test {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl pallet_balances::Config for Test {
	type MaxLocks = ();
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type Balance = u64;
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ConstU64<1>;
	type AccountStore = System;
	type WeightInfo = ();
	type FreezeIdentifier = ();
	type MaxFreezes = ();
	type RuntimeHoldReason = ();
	type MaxHolds = ();
}

// Mock verifier
pub struct MockVerifier;

impl Verifier for MockVerifier {
	fn verify(message: &Message) -> Result<Log, DispatchError> {
		let log: Log = rlp::decode(&message.data).unwrap();
		Ok(log)
	}
}

parameter_types! {
	pub const EthereumNetwork: xcm::v3::NetworkId = xcm::v3::NetworkId::Ethereum { chain_id: 15};
}

impl inbound_queue::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type Verifier = MockVerifier;
	type Token = Balances;
	type Reward = ConstU64<100>;
	type XcmSender = ();
	type WeightInfo = ();
	type AllowListLength = ConstU32<2>;
}

fn last_events(n: usize) -> Vec<RuntimeEvent> {
	frame_system::Pallet::<Test>::events()
		.into_iter()
		.rev()
		.take(n)
		.rev()
		.map(|e| e.event)
		.collect()
}

fn expect_events(e: Vec<RuntimeEvent>) {
	assert_eq!(last_events(e.len()), e);
}

pub fn new_tester(outbound_queue_address: H160) -> sp_io::TestExternalities {
	new_tester_with_config(inbound_queue::GenesisConfig { allowlist: vec![outbound_queue_address] })
}

pub fn new_tester_with_config(config: inbound_queue::GenesisConfig) -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

	GenesisBuild::<Test>::assimilate_storage(&config, &mut storage).unwrap();

	let mut ext: sp_io::TestExternalities = storage.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn parse_dest(message: Message) -> ParaId {
	let log = MockVerifier::verify(&message)
		.map_err(|err| {
			println!("mock verify: {:?}", err);
			err
		})
		.unwrap();
	let envelope = Envelope::try_from(log)
		.map_err(|err| {
			println!("envelope: {:?}", err);
			err
		})
		.unwrap();
	envelope.dest
}

// The originating channel address for the messages below
const OUTBOUND_QUEUE_ADDRESS: [u8; 20] = hex!["87d1f7fdfEe7f651FaBc8bFCB6E086C278b77A7d"];

const OUTBOUND_QUEUE_EVENT_LOG: [u8; 254] = hex!(
	"
	f8fc9487d1f7fdfee7f651fabc8bfcb6e086c278b77a7df863a01b11dcf133cc240f682dab2d3a8e4cd35c5da8c9cf99adac4336f8512584c5ada000000000000000000000000000000000000000000000000000000000000003e8a00000000000000000000000000000000000000000000000000000000000000001b880000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000290001f8f7758fbcefd546eaeff7de24aff666b6228e730000000000e8890423c78a00000000000000000000000000000000000000000000000000000000000000
	"
);

use snowbridge_core::ParaId;

#[test]
fn test_submit() {
	new_tester(OUTBOUND_QUEUE_ADDRESS.into()).execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Deposit funds into sovereign account of Asset Hub (Statemint)
		let dest_para: ParaId = 1000u32.into();
		let sovereign_account: AccountId = dest_para.into_account_truncating();
		println!("account: {}", sovereign_account);
		let _ = Balances::mint_into(&sovereign_account, 10000);

		// Submit message
		let message = Message {
			data: OUTBOUND_QUEUE_EVENT_LOG.into(),
			proof: Proof {
				block_hash: Default::default(),
				tx_index: Default::default(),
				data: Default::default(),
			},
		};
		assert_ok!(InboundQueue::submit(origin.clone(), message.clone()));
		expect_events(vec![InboundQueueEvent::MessageReceived {
			dest: dest_para,
			nonce: 1,
			// dummy xcm sender doesn't actually send messages
			result: MessageDispatchResult::InvalidPayload,
		}
		.into()]);
	});
}

#[test]
fn test_submit_with_invalid_outbound_queue() {
	new_tester(H160::zero()).execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Deposit funds into sovereign account of Asset Hub (Statemint)
		let dest_para: ParaId = 1000u32.into();
		let sovereign_account: AccountId = dest_para.into_account_truncating();
		let _ = Balances::mint_into(&sovereign_account, 10000);

		// Submit message
		let message = Message {
			data: OUTBOUND_QUEUE_EVENT_LOG.into(),
			proof: Proof {
				block_hash: Default::default(),
				tx_index: Default::default(),
				data: Default::default(),
			},
		};
		assert_noop!(
			InboundQueue::submit(origin.clone(), message.clone()),
			Error::<Test>::InvalidOutboundQueue
		);
	});
}

#[test]
fn test_submit_with_invalid_nonce() {
	new_tester(OUTBOUND_QUEUE_ADDRESS.into()).execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Deposit funds into sovereign account of Asset Hub (Statemint)
		let dest_para: ParaId = 1000u32.into();
		let sovereign_account: AccountId = dest_para.into_account_truncating();
		let _ = Balances::mint_into(&sovereign_account, 10000);

		// Submit message
		let message = Message {
			data: OUTBOUND_QUEUE_EVENT_LOG.into(),
			proof: Proof {
				block_hash: Default::default(),
				tx_index: Default::default(),
				data: Default::default(),
			},
		};
		assert_ok!(InboundQueue::submit(origin.clone(), message.clone()));

		let event_dest = parse_dest(message.clone());
		let nonce: u64 = <Nonce<Test>>::get(event_dest);
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
	new_tester(OUTBOUND_QUEUE_ADDRESS.into()).execute_with(|| {
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);

		// Create sovereign account for Asset Hub (Statemint), but with no funds to cover rewards
		let dest_para: ParaId = 1000u32.into();
		let sovereign_account: AccountId = dest_para.into_account_truncating();
		assert_ok!(Balances::mint_into(&sovereign_account, 2));

		// Submit message
		let message = Message {
			data: OUTBOUND_QUEUE_EVENT_LOG.into(),
			proof: Proof {
				block_hash: Default::default(),
				tx_index: Default::default(),
				data: Default::default(),
			},
		};
		assert_noop!(
			InboundQueue::submit(origin.clone(), message.clone()),
			// should actually be `NoFunds`. See this bug in substrate:
			// https://github.com/paritytech/substrate/issues/13866
			ArithmeticError::Underflow
		);
	});
}

#[test]
fn test_add_allow_list_without_root_yields_bad_origin() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let contract_address = hex!("0000000000000000000000000000000000000000").into();
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);
		assert_noop!(
			InboundQueue::add_allow_list(origin, contract_address),
			sp_runtime::DispatchError::BadOrigin,
		);
	});
}

#[test]
fn test_add_allow_list_with_root_succeeds() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let origin = RuntimeOrigin::root();
		let contract_address = hex!("0000000000000000000000000000000000000000").into();

		assert_eq!(<AllowList<Test>>::get().len(), 0);
		assert_ok!(InboundQueue::add_allow_list(origin, contract_address));

		System::assert_last_event(RuntimeEvent::InboundQueue(crate::Event::AllowListAdded {
			address: contract_address,
		}));

		assert_eq!(<AllowList<Test>>::get().len(), 1);
		assert!(<AllowList<Test>>::get().contains(&contract_address));
	});
}

#[test]
fn test_add_allow_list_ignores_duplicates() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let origin = RuntimeOrigin::root();
		let contract_address = hex!("0000000000000000000000000000000000000000").into();

		assert_eq!(<AllowList<Test>>::get().len(), 0);
		assert_ok!(InboundQueue::add_allow_list(origin.clone(), contract_address));
		assert_eq!(<AllowList<Test>>::get().len(), 1);
		assert!(<AllowList<Test>>::get().contains(&contract_address));
		assert_ok!(InboundQueue::add_allow_list(origin, contract_address));
		assert_eq!(<AllowList<Test>>::get().len(), 1);
		assert!(<AllowList<Test>>::get().contains(&contract_address));
	});
}

#[test]
fn test_add_allow_list_fails_when_exceeding_bounds() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let origin = RuntimeOrigin::root();
		let contract_address1 = hex!("0000000000000000000000000000000000000000").into();
		let contract_address2 = hex!("1000000000000000000000000000000000000000").into();
		let contract_address3 = hex!("3000000000000000000000000000000000000000").into();

		assert_eq!(<AllowList<Test>>::get().len(), 0);

		assert_ok!(InboundQueue::add_allow_list(origin.clone(), contract_address1));
		assert_eq!(<AllowList<Test>>::get().len(), 1);

		assert_ok!(InboundQueue::add_allow_list(origin.clone(), contract_address2));
		assert_eq!(<AllowList<Test>>::get().len(), 2);

		assert_noop!(
			InboundQueue::add_allow_list(origin, contract_address3),
			Error::<Test>::AllowListFull,
		);
		assert_eq!(<AllowList<Test>>::get().len(), 2);
	});
}

#[test]
fn test_remove_allow_list_without_root_yields_bad_origin() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let contract_address = hex!("0000000000000000000000000000000000000000").into();
		let relayer: AccountId = Keyring::Bob.into();
		let origin = RuntimeOrigin::signed(relayer);
		assert_noop!(
			InboundQueue::remove_allow_list(origin, contract_address),
			sp_runtime::DispatchError::BadOrigin,
		);
	});
}

#[test]
fn test_remove_allow_list_with_root_succeeds() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let origin = RuntimeOrigin::root();
		let contract_address = hex!("0000000000000000000000000000000000000000").into();

		assert_eq!(<AllowList<Test>>::get().len(), 0);
		assert_ok!(InboundQueue::add_allow_list(origin.clone(), contract_address));
		assert_eq!(<AllowList<Test>>::get().len(), 1);

		assert_ok!(InboundQueue::remove_allow_list(origin, contract_address));
		System::assert_last_event(RuntimeEvent::InboundQueue(crate::Event::AllowListRemoved {
			address: contract_address,
		}));

		assert_eq!(<AllowList<Test>>::get().len(), 0);
		assert!(!<AllowList<Test>>::get().contains(&contract_address));
	});
}

#[test]
fn test_remove_allow_list_event_not_emitted_for_none_existent_item() {
	new_tester_with_config(Default::default()).execute_with(|| {
		let origin = RuntimeOrigin::root();
		let contract_address = hex!("0000000000000000000000000000000000000000").into();

		let start = System::event_count();
		assert_ok!(InboundQueue::remove_allow_list(origin, contract_address));
		let end = System::event_count();

		assert_eq!(start, end); // No new events
	});
}
