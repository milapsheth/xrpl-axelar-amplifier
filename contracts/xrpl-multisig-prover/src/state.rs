use axelar_wasm_std::Threshold;
use cosmwasm_std::{Addr, HexBinary};
use cw_storage_plus::{Item, Map};
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct Config {
    pub axelar_multisig_address: Addr,
    pub gateway_address: Addr,
    pub signing_threshold: Threshold,
    pub xrpl_multisig_address: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const KEY_ID: Item<String> = Item::new("key_id");
pub const REPLY_TX_HASH: Item<HexBinary> = Item::new("reply_tx_hash");
pub const MULTISIG_SESSION_TX: Map<u64, HexBinary> = Map::new("multisig_session_tx");
