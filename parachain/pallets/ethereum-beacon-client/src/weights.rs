//! Autogenerated weights for ethereum_beacon_client
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-09-27, STEPS: `10`, REPEAT: 10, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("/tmp/snowbridge/spec.json"), DB CACHE: 1024

// Executed Command:
// ./target/release/snowbridge
// benchmark
// pallet
// --chain
// /tmp/snowbridge/spec.json
// --execution=wasm
// --pallet
// ethereum_beacon_client
// --extrinsic
// *
// --steps
// 10
// --repeat
// 10
// --output
// pallets/ethereum-beacon-client/src/weights.rs
// --template
// templates/module-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for ethereum_beacon_client.
pub trait WeightInfo {
	fn force_checkpoint() -> Weight;
	fn submit() -> Weight;
	fn submit_with_sync_committee() -> Weight;
	fn submit_execution_header() -> Weight;
}

// For backwards compatibility and tests
impl WeightInfo for () {
	fn force_checkpoint() -> Weight {
		Weight::from_parts(97_263_571_000 as u64, 0)
			.saturating_add(Weight::from_parts(0, 3501))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(9))
	}
	fn submit() -> Weight {
		Weight::from_parts(26_051_019_000 as u64, 0)
			.saturating_add(Weight::from_parts(0, 93857))
			.saturating_add(RocksDbWeight::get().reads(8))
			.saturating_add(RocksDbWeight::get().writes(4))
	}
	fn submit_with_sync_committee() -> Weight {
		Weight::from_parts(122_461_312_000 as u64, 0)
			.saturating_add(Weight::from_parts(0, 93857))
			.saturating_add(RocksDbWeight::get().reads(6))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	fn submit_execution_header() -> Weight {
		Weight::from_parts(113_158_000 as u64, 0)
			.saturating_add(Weight::from_parts(0, 3537))
			.saturating_add(RocksDbWeight::get().reads(5))
			.saturating_add(RocksDbWeight::get().writes(4))
	}
}
