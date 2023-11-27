use std::fmt;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Key, Item, Map, PrimaryKey};

use axelar_wasm_std::{
    counter, nonempty,
    operators::Operators,
    voting::{PollID, WeightedPoll},
    Threshold,
};
use connection_router::state::{ChainName, CrossChainId, Message};

use crate::execute::MessageStatus;

#[cw_serde]
pub struct Config {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: Threshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
}

#[cw_serde]
pub enum Poll {
    Messages(WeightedPoll),
    ConfirmWorkerSet(WeightedPoll),
    ConfirmMessageStatus(WeightedPoll),
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct MessageId(pub nonempty::String);

impl fmt::Display for MessageId {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "{}", self.0.as_str())
    }
}

impl PrimaryKey<'_> for MessageId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = String;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

pub const POLL_ID: counter::Counter<PollID> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollID, Poll> = Map::new("polls");

pub const PENDING_MESSAGES: Map<PollID, Vec<Message>> = Map::new("pending_messages");

pub const VERIFIED_MESSAGES: Map<&CrossChainId, Message> = Map::new("verified_messages");

pub const PENDING_MESSAGE_STATUSES: Map<PollID, Vec<(MessageId, MessageStatus)>> = Map::new("pending_message_statuses");

pub const CONFIRMED_MESSAGE_STATUSES: Map<&MessageId, MessageStatus> = Map::new("confirmed_message_statuses");

pub const CONFIG: Item<Config> = Item::new("config");

type OperatorsHash = Vec<u8>;
pub const CONFIRMED_WORKER_SETS: Map<OperatorsHash, ()> = Map::new("confirmed_worker_sets");

pub const PENDING_WORKER_SETS: Map<PollID, Operators> = Map::new("pending_worker_sets");
