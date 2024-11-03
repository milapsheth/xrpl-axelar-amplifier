use crate::axelar_workers::VerifierSet;
use axelar_wasm_std::MajorityThreshold;
use router_api::{ChainName, CrossChainId};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use xrpl_types::types::*;

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub governance: Addr,
    pub axelar_multisig: Addr,
    pub coordinator: Addr,
    pub gateway: Addr,
    pub signing_threshold: MajorityThreshold,
    pub xrpl_multisig: String,
    pub voting_verifier: Addr,
    pub service_registry: Addr,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
    pub key_type: multisig::key::KeyType,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const REPLY_TX_HASH: Item<TxHash> = Item::new("reply_tx_hash");
pub const REPLY_MESSAGE_ID: Item<CrossChainId> = Item::new("reply_message_id");
pub const MULTISIG_SESSION_ID_TO_TX_HASH: Map<u64, TxHash> = Map::new("multisig_session_tx");

// The next seq. no. is affected by the number of tickets created,
// not solely on the last sequence number used.
// On the contrary, the next ticket number to be used cannot be determined before proof construction,
// as it depends on the tickets available at the time.
// After all ticket numbers are used, we reuse the smallest available ticket number,
// going over all ticket numbers again, wrapping around.
pub const NEXT_SEQUENCE_NUMBER: Item<u32> = Item::new("next_sequence_number");
pub const LAST_ASSIGNED_TICKET_NUMBER: Item<u32> = Item::new("last_assigned_ticket_number");

#[cw_serde]
pub struct MultisigSession { // TODO: rename
    pub id: u64,
    pub expires_at: u64,
}

pub const MESSAGE_ID_TO_TICKET: Map<&CrossChainId, u32> = Map::new("message_id_to_ticket");
pub const MESSAGE_ID_TO_MULTISIG_SESSION: Map<&CrossChainId, MultisigSession> =
    Map::new("message_id_to_multisig_session");
pub const CONFIRMED_TRANSACTIONS: Map<&u32, TxHash> = Map::new("confirmed_transactions");
pub const AVAILABLE_TICKETS: Item<Vec<u32>> = Item::new("available_tickets");
pub const TRANSACTION_INFO: Map<&TxHash, TransactionInfo> = Map::new("transaction_info");
pub const LATEST_SEQUENTIAL_TX_HASH: Item<TxHash> = Item::new("latest_sequential_tx_hash");

#[cw_serde]
pub struct TokenInfo {
    pub xrpl_token: XRPLToken,
    pub decimals: u8,
}

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");
