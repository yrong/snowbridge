mod asset_hub_runtime;
mod bridge_hub_runtime;
mod chopsticks;
mod commands;
mod constants;
mod helpers;
mod relay_runtime;

use alloy_primitives::{utils::parse_units, Address, Bytes, FixedBytes, U128, U256};
use chopsticks::generate_chopsticks_script;
use clap::{Args, Parser, Subcommand, ValueEnum};
use codec::Encode;
use constants::{ASSET_HUB_API, BRIDGE_HUB_API, POLKADOT_DECIMALS, POLKADOT_SYMBOL, RELAY_API};
use helpers::{
    force_xcm_version, instant_payout, schedule_payout, send_xcm_asset_hub, send_xcm_bridge_hub,
    utility_force_batch, vesting_payout,
};
use sp_crypto_hashing::blake2_256;
use std::{io::Write, path::PathBuf};
use subxt::{OnlineClient, PolkadotConfig};

#[derive(Debug, Parser)]
#[command(name = "snowbridge-preimage", version, about, long_about = None)]
struct Cli {
    /// Output format of preimage
    #[arg(long, value_enum, default_value_t=Format::Hex)]
    format: Format,

    #[command(flatten)]
    api_endpoints: ApiEndpoints,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize the bridge
    Initialize(InitializeArgs),
    /// Update the asset on AssetHub
    UpdateAsset(UpdateAssetArgs),
    /// Upgrade the Gateway contract
    Upgrade(UpgradeArgs),
    /// Change the gateway operating mode
    GatewayOperatingMode(GatewayOperatingModeArgs),
    /// Set pricing parameters
    PricingParameters(PricingParametersArgs),
    /// Set the checkpoint for the beacon light client
    ForceCheckpoint(ForceCheckpointArgs),
    /// Treasury proposal
    TreasuryProposal2024,
}

#[derive(Debug, Args)]
pub struct InitializeArgs {
    #[command(flatten)]
    gateway_operating_mode: GatewayOperatingModeArgs,
    #[command(flatten)]
    pricing_parameters: PricingParametersArgs,
    #[command(flatten)]
    force_checkpoint: ForceCheckpointArgs,
    #[command(flatten)]
    gateway_address: GatewayAddressArgs,
}

#[derive(Debug, Args)]
pub struct UpdateAssetArgs {
    /// Chain ID of the Ethereum chain bridge from.
    #[arg(long, value_name = "ADDRESS", value_parser=parse_eth_address_without_validation)]
    contract_id: Address,
    /// The asset display name, e.g. Wrapped Ether
    #[arg(long, value_name = "ASSET_DISPLAY_NAME")]
    name: String,
    /// The asset symbol, e.g. WETH
    #[arg(long, value_name = "ASSET_SYMBOL")]
    symbol: String,
    /// The asset's number of decimal places.
    #[arg(long, value_name = "DECIMALS")]
    decimals: u8,
    /// The minimum balance of the asset.
    #[arg(long, value_name = "MIN_BALANCE")]
    min_balance: u128,
    /// Should the asset be sufficient.
    #[arg(long, value_name = "IS_SUFFICIENT")]
    is_sufficient: bool,
    /// Should the asset be frozen.
    #[arg(long, value_name = "IS_FROZEN")]
    is_frozen: bool,
}

#[derive(Debug, Args)]
pub struct UpgradeArgs {
    /// Address of the logic contract
    #[arg(long, value_name = "ADDRESS", value_parser=parse_eth_address)]
    logic_address: Address,

    /// Hash of the code in the logic contract
    #[arg(long, value_name = "HASH", value_parser=parse_hex_bytes32)]
    logic_code_hash: FixedBytes<32>,

    /// Initialize the logic contract
    #[arg(long, requires_all=["initializer_params", "initializer_gas"])]
    initializer: bool,

    /// ABI-encoded params to pass to initializer
    #[arg(long, requires = "initializer", value_name = "BYTES", value_parser=parse_hex_bytes)]
    initializer_params: Option<Bytes>,

    /// Maximum gas required by the initializer
    #[arg(long, requires = "initializer", value_name = "GAS")]
    initializer_gas: Option<u64>,
}

#[derive(Debug, Args)]
pub struct GatewayOperatingModeArgs {
    /// Operating mode
    #[arg(long, value_enum)]
    gateway_operating_mode: GatewayOperatingModeEnum,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
pub enum GatewayOperatingModeEnum {
    Normal,
    RejectingOutboundMessages,
}

#[derive(Debug, Args)]
pub struct GatewayAddressArgs {
    /// Address of the contract on Ethereum
    #[arg(long, value_name = "ADDRESS")]
    pub gateway_address: Address,
}

#[derive(Debug, Args)]
pub struct ForceCheckpointArgs {
    /// Path to JSON file containing checkpoint
    #[arg(long, value_name = "FILE")]
    pub checkpoint: PathBuf,
}

#[derive(Debug, Args)]
pub struct PricingParametersArgs {
    /// Numerator for ETH/DOT Exchange rate
    ///
    /// For example, if the exchange rate is 1/400 (exchange 1 ETH for 400 DOT), then NUMERATOR should be 1.
    #[arg(long, value_name = "UINT")]
    pub exchange_rate_numerator: u64,
    /// Denominator for ETH/DOT Exchange rate
    ///
    /// For example, if the exchange rate is 1/400 (exchange 1 ETH for 400 DOT), then DENOMINATOR should be 400.
    #[arg(long, value_name = "UINT")]
    pub exchange_rate_denominator: u64,
    /// Numerator for Multiplier
    ///
    /// For example, if the multiplier is 4/3, then NUMERATOR should be 4.
    #[arg(long, value_name = "UINT")]
    pub multiplier_numerator: u64,
    /// Denominator for Multiplier
    ///
    /// For example, if the multiplier is 4/3, then DENOMINATOR should be 3.
    #[arg(long, value_name = "UINT")]
    pub multiplier_denominator: u64,
    /// Ether fee per unit of gas
    #[arg(long, value_name = "GWEI", value_parser = parse_units_gwei)]
    pub fee_per_gas: U256,
    /// Relayer reward for delivering messages to Polkadot
    #[arg(long, value_name = POLKADOT_SYMBOL, value_parser = parse_units_polkadot)]
    pub local_reward: U128,
    /// Relayer reward for delivering messages to Ethereum
    #[arg(long, value_name = "ETHER", value_parser = parse_units_eth)]
    pub remote_reward: U256,
}

#[derive(Debug, Args)]
pub struct ApiEndpoints {
    #[arg(long, value_name = "URL")]
    bridge_hub_api: Option<String>,

    #[arg(long, value_name = "URL")]
    asset_hub_api: Option<String>,

    #[arg(long, value_name = "URL")]
    relay_api: Option<String>,
}

fn parse_eth_address(v: &str) -> Result<Address, String> {
    Address::parse_checksummed(v, None).map_err(|_| "invalid ethereum address".to_owned())
}
use hex_literal::hex;
use std::str::FromStr;

fn parse_eth_address_without_validation(v: &str) -> Result<Address, String> {
    Address::from_str(v).map_err(|_| "invalid ethereum address".to_owned())
}

fn parse_hex_bytes32(v: &str) -> Result<FixedBytes<32>, String> {
    v.parse::<FixedBytes<32>>()
        .map_err(|_| "invalid 32-byte hex value".to_owned())
}

fn parse_hex_bytes(v: &str) -> Result<Bytes, String> {
    v.parse::<Bytes>()
        .map_err(|_| "invalid hex value".to_owned())
}

fn parse_units_polkadot(v: &str) -> Result<U128, String> {
    let amount = parse_units(v, POLKADOT_DECIMALS).map_err(|e| format!("{e}"))?;
    let amount: U256 = amount.into();
    let amount: U128 = amount.to::<U128>();
    Ok(amount)
}

fn parse_units_gwei(v: &str) -> Result<U256, String> {
    let amount = parse_units(v, "gwei").map_err(|e| format!("{e}"))?;
    Ok(amount.into())
}

fn parse_units_eth(v: &str) -> Result<U256, String> {
    let amount = parse_units(v, "ether").map_err(|e| format!("{e}"))?;
    Ok(amount.into())
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
pub enum Format {
    Hex,
    Binary,
}

struct Context {
    bridge_hub_api: Box<OnlineClient<PolkadotConfig>>,
    asset_hub_api: Box<OnlineClient<PolkadotConfig>>,
    relay_api: Box<OnlineClient<PolkadotConfig>>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let bridge_hub_api: OnlineClient<PolkadotConfig> = OnlineClient::from_url(
        cli.api_endpoints
            .bridge_hub_api
            .unwrap_or(BRIDGE_HUB_API.to_owned()),
    )
    .await?;

    let asset_hub_api: OnlineClient<PolkadotConfig> = OnlineClient::from_url(
        cli.api_endpoints
            .asset_hub_api
            .unwrap_or(ASSET_HUB_API.to_owned()),
    )
    .await?;

    let relay_api: OnlineClient<PolkadotConfig> =
        OnlineClient::from_url(cli.api_endpoints.relay_api.unwrap_or(RELAY_API.to_owned())).await?;

    let context = Context {
        bridge_hub_api: Box::new(bridge_hub_api),
        asset_hub_api: Box::new(asset_hub_api),
        relay_api: Box::new(relay_api),
    };

    let call = match &cli.command {
        Command::ForceCheckpoint(params) => {
            let call = commands::force_checkpoint(params);
            send_xcm_bridge_hub(&context, vec![call]).await?
        }
        Command::Initialize(params) => {
            let (set_pricing_parameters, set_ethereum_fee) =
                commands::pricing_parameters(&context, &params.pricing_parameters).await?;
            let call1 = send_xcm_bridge_hub(
                &context,
                vec![
                    commands::set_gateway_address(&params.gateway_address),
                    set_pricing_parameters,
                    commands::gateway_operating_mode(&params.gateway_operating_mode),
                    commands::force_checkpoint(&params.force_checkpoint),
                ],
            )
            .await?;
            let call2 =
                send_xcm_asset_hub(&context, vec![force_xcm_version(), set_ethereum_fee]).await?;
            utility_force_batch(vec![call1, call2])
        }
        Command::UpdateAsset(params) => {
            send_xcm_asset_hub(
                &context,
                vec![
                    commands::make_asset_sufficient(params),
                    commands::force_set_metadata(params),
                ],
            )
            .await?
        }
        Command::GatewayOperatingMode(params) => {
            let call = commands::gateway_operating_mode(params);
            send_xcm_bridge_hub(&context, vec![call]).await?
        }
        Command::Upgrade(params) => {
            let call = commands::upgrade(params);
            send_xcm_bridge_hub(&context, vec![call]).await?
        }
        Command::PricingParameters(params) => {
            let (set_pricing_parameters, set_ethereum_fee) =
                commands::pricing_parameters(&context, params).await?;
            let call1 = send_xcm_bridge_hub(&context, vec![set_pricing_parameters]).await?;
            let call2 = send_xcm_asset_hub(&context, vec![set_ethereum_fee]).await?;
            utility_force_batch(vec![call1, call2])
        }
        Command::TreasuryProposal2024 => {
            let beneficiary: [u8; 32] =
                hex!("40ff75e9f6e5eea6579fd37a8296c58b0ff0f0940ea873e5d26b701163b1b325");

            let mut scheduled_calls: Vec<
                polkadot_runtime::api::runtime_types::polkadot_runtime::RuntimeCall,
            > = vec![];

            // Immediate direct payout of 191379 DOT
            let instant_pay_amount: u128 = 1913790000000000;
            let call = instant_payout(&context, instant_pay_amount, beneficiary).await?;
            scheduled_calls.push(call);

            // Immediate 2-year vesting payout of 323275 DOT
            let vesting_pay_amount: u128 = 3232750000000000;
            let vesting_period: u32 = 2 * 365 * 24 * 3600 / 6;
            let per_block: u128 = vesting_pay_amount / (vesting_period as u128);
            let treasury: [u8; 32] =
                hex!("6d6f646c70792f74727372790000000000000000000000000000000000000000");
            // consider the proposal unconfirmed, start vesting after 45 days to make sure the
            // starting_block is valid.
            let delay: u32 = 45 * 24 * 3600 / 6;
            let call = vesting_payout(
                &context,
                vesting_pay_amount,
                per_block,
                treasury,
                beneficiary,
                delay,
            )
            .await?;
            scheduled_calls.push(call);

            // Scheduled payout in 75 days from now of 161637 DOT
            let scheduled_pay_amount: u128 = 1616370000000000;
            let delay: u32 = 75 * 24 * 3600 / 6;
            let call = schedule_payout(&context, scheduled_pay_amount, beneficiary, delay).await?;
            scheduled_calls.push(call);

            // 6 x scheduled payouts of 53879 DOT each, starting 3.5 months from now
            // and repeating 6 times from Sept 2024 - Feb 2025 every month
            let scheduled_pay_amount: u128 = 538790000000000;
            let mut delay: u32 = 105 * 24 * 3600 / 6;
            for _ in 0..6 {
                let call =
                    schedule_payout(&context, scheduled_pay_amount, beneficiary, delay).await?;
                scheduled_calls.push(call);
                delay = delay + (30 * 24 * 3600 / 6)
            }

            utility_force_batch(scheduled_calls)
        }
    };

    let preimage = call.encode();

    generate_chopsticks_script(&preimage, "chopsticks-execute-upgrade.js".into())?;

    eprintln!("Preimage Hash: 0x{}", hex::encode(blake2_256(&preimage)));
    eprintln!("Preimage Size: {}", preimage.len());

    match cli.format {
        Format::Hex => {
            println!("0x{}", hex::encode(preimage));
        }
        Format::Binary => {
            std::io::stdout().write_all(&preimage)?;
        }
    }

    Ok(())
}
