use std::{num::NonZeroU32, collections::BTreeSet};

use axelar_wasm_std::{Participant, nonempty::Uint256};
use cosmwasm_std::{Addr, HexBinary};
use cw_storage_plus::{Item, Map};
use cosmwasm_schema::cw_serde;
use multisig::{key::PublicKey, msg::Signer};
use sha3::{Digest, Keccak256};
use crate::types::{TransactionInfo, TxHash, XRPLToken};

#[cw_serde]
pub struct Config {
    pub axelar_multisig_address: Addr,
    pub gateway_address: Addr,
    pub signing_quorum: NonZeroU32,
    pub xrpl_multisig_address: Addr,
    pub voting_verifier_address: Addr,
    pub service_registry_address: Addr,
    pub service_name: String,
    pub worker_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub last_ledger_sequence_offset: u32,
    pub ticket_count_threshold: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const REPLY_TX_HASH: Item<TxHash> = Item::new("reply_tx_hash");
pub const MULTISIG_SESSION_TX: Map<u64, TxHash> = Map::new("multisig_session_tx");

// The next seq. no. is determined on TicketCreate and depends on the number of created tickets,
// not solely on the last sequence number used.
// On the contrary, the next ticket number to be used cannot be determined before proof construction,
// as it depends on the tickets available at the time.
// After all ticket numbers are used, we reuse the smallest available ticket number,
// going over all ticket numbers again, wrapping around.
pub const NEXT_SEQUENCE_NUMBER: Item<u32> = Item::new("next_sequence_number");
pub const LAST_ASSIGNED_TICKET_NUMBER: Item<u32> = Item::new("last_assigned_ticket_number");

pub const AVAILABLE_TICKETS: Item<Vec<u32>> = Item::new("available_tickets");
pub const TRANSACTION_INFO: Map<TxHash, TransactionInfo> = Map::new("transaction_info");
pub const LATEST_TICKET_CREATE_TX_HASH: Item<TxHash> = Item::new("latest_ticket_create_tx_hash");

pub const TOKENS: Map<String, XRPLToken> = Map::new("tokens");

#[cw_serde]
pub struct WorkerSet {
    pub signers: BTreeSet<Signer>,
    pub threshold: Uint256,
    // for hash uniqueness. The same exact worker set could be in use at two different times,
    // and we need to be able to distinguish between the two
    pub created_at: u64,
}

impl WorkerSet {
    pub fn new(
        participants: Vec<(Participant, PublicKey)>,
        threshold: Uint256,
        block_height: u64,
    ) -> Self {
        let signers = participants
            .into_iter()
            .map(|(participant, pub_key)| Signer {
                address: participant.address.clone(),
                weight: participant.weight.into(),
                pub_key,
            })
            .collect();

        WorkerSet {
            signers,
            threshold,
            created_at: block_height,
        }
    }

    pub fn hash(&self) -> HexBinary {
        Keccak256::digest(serde_json::to_vec(&self).expect("couldn't serialize worker set"))
            .as_slice()
            .into()
    }

    pub fn id(&self) -> String {
        self.hash().to_hex()
    }
}

pub const CURRENT_WORKER_SET: Item<WorkerSet> = Item::new("current_worker_set");
pub const NEXT_WORKER_SET: Map<TxHash, (WorkerSet, Uint256)> = Map::new("next_worker_set");
