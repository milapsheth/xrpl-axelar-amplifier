use axelar_wasm_std::voting::{PollId, PollStatus, Vote, WeightedPoll};
use axelar_wasm_std::{nonempty, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::EnsurePermissions;
use router_api::{Address, ChainName, FIELD_DELIMITER};
use sha3::{Keccak256, Digest};
use xrpl_multisig_prover::types::{XRPLPaymentAmount, XRPLAccountId};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can call all messages of unrestricted governance permission level, like UpdateVotingThreshold.
    /// It can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet it should match the address of the Cosmos governance module.
    pub governance_address: nonempty::String,
    /// Service registry contract address on axelar.
    pub service_registry_address: nonempty::String,
    /// Name of service in the service registry for which verifiers are registered.
    pub service_name: nonempty::String,
    /// Axelar's gateway contract address on the source chain
    pub source_gateway_address: nonempty::String,
    /// Threshold of weighted votes required for voting to be considered complete for a particular message
    pub voting_threshold: MajorityThreshold,
    /// The number of blocks after which a poll expires
    pub block_expiry: nonempty::Uint64,
    /// The number of blocks to wait for on the source chain before considering a transaction final
    pub confirmation_height: u64,
    /// Rewards contract address on axelar.
    pub rewards_address: nonempty::String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    // Computes the results of a poll
    // For all verified messages, calls MessagesVerified on the verifier
    #[permission(Any)]
    EndPoll { poll_id: PollId },

    // Casts votes for specified poll
    #[permission(Any)]
    Vote { poll_id: PollId, votes: Vec<Vote> },

    // returns a vector of true/false values, indicating current verification status for each message
    // starts a poll for any not yet verified messages
    #[permission(Any)]
    VerifyMessages(Vec<XRPLMessage>),

    // Update the threshold used for new polls. Callable only by governance
    #[permission(Governance)]
    UpdateVotingThreshold {
        new_voting_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub enum PollData {
    Messages(Vec<XRPLMessage>),
}
#[cw_serde]
pub struct PollResponse {
    pub poll: WeightedPoll,
    pub data: PollData,
    pub status: PollStatus,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(PollResponse)]
    Poll { poll_id: PollId },

    #[returns(Vec<MessageStatus>)]
    MessagesStatus(Vec<XRPLMessage>),

    #[returns(MajorityThreshold)]
    CurrentThreshold,
}

#[cw_serde]
pub struct MessageStatus {
    pub message: XRPLMessage,
    pub status: VerificationStatus,
}

impl MessageStatus {
    pub fn new(message: XRPLMessage, status: VerificationStatus) -> Self {
        Self { message, status }
    }
}

pub const CHAIN_NAME: &str = "xrpl"; // TODO

pub struct MemoDetails {
    pub destination_chain: ChainName,
    pub destination_address: Address,
    pub payload_hash: [u8; 32],
}

pub type XRPLHash = [u8; 32];

#[cw_serde]
pub enum XRPLMessage {
    ProverMessage(XRPLHash),
    UserMessage(UserMessage),
}

impl XRPLMessage {
    pub fn tx_id(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(tx_id) => *tx_id,
            XRPLMessage::UserMessage(user_message) => user_message.tx_id,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(tx_id) => *tx_id,
            XRPLMessage::UserMessage(user_message) => user_message.hash(),
        }
    }
}

#[cw_serde]
pub struct UserMessage {
    pub tx_id: XRPLHash, // TODO: use TxHash from xrpl_multisig_prover
    pub source_address: XRPLAccountId,
    pub destination_chain: ChainName,
    pub destination_address: Address,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
    pub amount: XRPLPaymentAmount,
}

impl UserMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8]; // TODO: check if this works for XRPL too

        hasher.update(self.tx_id);
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.to_bytes());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.payload_hash);

        hasher.finalize().into()
    }
}
