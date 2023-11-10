use axelar_wasm_std::Threshold;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use cosmwasm_schema::cw_serde;
use crate::types::{TransactionInfo, TxHash, XRPLToken};

#[cw_serde]
pub struct Config {
    pub axelar_multisig_address: Addr,
    pub gateway_address: Addr,
    pub signing_threshold: Threshold,
    pub xrpl_multisig_address: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const KEY_ID: Item<String> = Item::new("key_id");
pub const REPLY_TX_HASH: Item<TxHash> = Item::new("reply_tx_hash");
pub const MULTISIG_SESSION_TX: Map<u64, TxHash> = Map::new("multisig_session_tx");

pub const NEXT_SEQUENCE_NUMBER: Item<u32> = Item::new("next_sequence_number");
pub const LAST_ASSIGNED_TICKET_NUMBER: Item<u32> = Item::new("last_assigned_ticket_number");
pub const AVAILABLE_TICKETS: Item<Vec<u32>> = Item::new("available_tickets");
pub const TRANSACTION_INFO: Map<TxHash, TransactionInfo> = Map::new("transaction_info");

pub const TOKENS: Map<String, XRPLToken> = Map::new("tokens");
