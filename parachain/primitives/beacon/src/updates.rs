use codec::{Decode, Encode};
use frame_support::{CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_std::prelude::*;

use crate::types::{BeaconHeader, ExecutionPayloadHeader, SyncAggregate, SyncCommittee};

#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo)]
#[cfg_attr(
	feature = "std",
	derive(serde::Serialize, serde::Deserialize),
	serde(deny_unknown_fields, bound(serialize = ""), bound(deserialize = ""))
)]
pub struct CheckpointUpdate<const COMMITTEE_SIZE: usize> {
	pub header: BeaconHeader,
	pub current_sync_committee: SyncCommittee<COMMITTEE_SIZE>,
	pub current_sync_committee_branch: Vec<H256>,
	pub validators_root: H256,
	pub import_time: u64,
}

impl<const COMMITTEE_SIZE: usize> Default for CheckpointUpdate<COMMITTEE_SIZE> {
	fn default() -> Self {
		CheckpointUpdate {
			header: Default::default(),
			current_sync_committee: Default::default(),
			current_sync_committee_branch: Default::default(),
			validators_root: Default::default(),
			import_time: Default::default(),
		}
	}
}

#[derive(
	Default, Encode, Decode, CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo,
)]
#[cfg_attr(
	feature = "std",
	derive(serde::Deserialize),
	serde(deny_unknown_fields, bound(serialize = ""), bound(deserialize = ""))
)]
pub struct SyncCommitteeUpdate<const COMMITTEE_SIZE: usize, const COMMITTEE_BITS_SIZE: usize> {
	pub attested_header: BeaconHeader,
	pub next_sync_committee: SyncCommittee<COMMITTEE_SIZE>,
	pub next_sync_committee_branch: Vec<H256>,
	pub finalized_header: BeaconHeader,
	pub finality_branch: Vec<H256>,
	pub sync_aggregate: SyncAggregate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>,
	pub signature_slot: u64,
	pub block_roots_root: H256,
	pub block_roots_branch: Vec<H256>,
}

#[derive(
	Default, Encode, Decode, CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo,
)]
#[cfg_attr(
	feature = "std",
	derive(serde::Deserialize),
	serde(deny_unknown_fields, bound(serialize = ""), bound(deserialize = ""))
)]
pub struct NextSyncCommitteeUpdate<const SYNC_COMMITTEE_SIZE: usize> {
	// actual sync committee
	pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
	// sync committee, ssz merkle proof.
	pub next_sync_committee_branch: Vec<H256>,
}

#[derive(
	Default, Encode, Decode, CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo,
)]
#[cfg_attr(
	feature = "std",
	derive(serde::Deserialize),
	serde(deny_unknown_fields, bound(serialize = ""), bound(deserialize = ""))
)]
pub struct FinalizedHeaderUpdate<const COMMITTEE_SIZE: usize, const COMMITTEE_BITS_SIZE: usize> {
	pub attested_header: BeaconHeader,
	pub finalized_header: BeaconHeader,
	pub finality_branch: Vec<H256>,
	pub sync_aggregate: SyncAggregate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>,
	pub signature_slot: u64,
	pub block_roots_root: H256,
	pub block_roots_branch: Vec<H256>,
}

#[derive(
	Default, Encode, Decode, CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo,
)]
#[cfg_attr(
	feature = "std",
	derive(serde::Deserialize),
	serde(deny_unknown_fields, bound(serialize = ""), bound(deserialize = ""))
)]
pub struct LightClientUpdate<const COMMITTEE_SIZE: usize, const COMMITTEE_BITS_SIZE: usize> {
	pub attested_header: BeaconHeader,
	pub finalized_header: BeaconHeader,
	pub finality_branch: Vec<H256>,
	pub sync_aggregate: SyncAggregate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>,
	pub signature_slot: u64,
	pub block_roots_root: H256,
	pub block_roots_branch: Vec<H256>,
	pub sync_committee_update: Option<NextSyncCommitteeUpdate<COMMITTEE_SIZE>>,
}

impl<const COMMITTEE_SIZE: usize, const COMMITTEE_BITS_SIZE: usize>
	From<FinalizedHeaderUpdate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>>
	for LightClientUpdate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>
{
	fn from(update: FinalizedHeaderUpdate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>) -> Self {
		LightClientUpdate::<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE> {
			attested_header: update.attested_header,
			finalized_header: update.finalized_header,
			finality_branch: update.finality_branch.clone(),
			sync_aggregate: update.sync_aggregate.clone(),
			signature_slot: update.signature_slot,
			block_roots_root: update.block_roots_root,
			block_roots_branch: update.block_roots_branch.clone(),
			sync_committee_update: None,
		}
	}
}

impl<const COMMITTEE_SIZE: usize, const COMMITTEE_BITS_SIZE: usize>
	From<SyncCommitteeUpdate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>>
	for LightClientUpdate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>
{
	fn from(update: SyncCommitteeUpdate<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE>) -> Self {
		LightClientUpdate::<COMMITTEE_SIZE, COMMITTEE_BITS_SIZE> {
			attested_header: update.attested_header,
			finalized_header: update.finalized_header,
			finality_branch: update.finality_branch.clone(),
			sync_aggregate: update.sync_aggregate.clone(),
			signature_slot: update.signature_slot,
			block_roots_root: update.block_roots_root,
			block_roots_branch: update.block_roots_branch.clone(),
			sync_committee_update: Some(NextSyncCommitteeUpdate {
				next_sync_committee: update.next_sync_committee.clone(),
				next_sync_committee_branch: update.next_sync_committee_branch.clone(),
			}),
		}
	}
}

#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, RuntimeDebugNoBound, TypeInfo)]
#[cfg_attr(
	feature = "std",
	derive(serde::Deserialize),
	serde(deny_unknown_fields, bound(serialize = ""), bound(deserialize = ""))
)]
pub struct ExecutionHeaderUpdate {
	pub header: BeaconHeader,
	pub execution_header: ExecutionPayloadHeader,
	pub execution_branch: Vec<H256>,
	pub block_roots_root: H256,
	pub block_roots_branch: Vec<H256>,
}
