use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use router_api::{ChainName, CrossChainId};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{HexBinary, Uint64};
use multisig::key::PublicKey;

use xrpl_types::types::{TxHash, XRPLToken};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin_address: String,
    pub axelar_multisig_address: String,
    pub gateway_address: String,
    pub signing_threshold: MajorityThreshold,
    pub xrpl_multisig_address: String,
    pub voting_verifier_address: String,
    pub service_registry_address: String,
    pub coordinator_address: String,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
    pub available_tickets: Vec<u32>,
    pub next_sequence_number: u32,
    pub last_assigned_ticket_number: u32,
    pub governance_address: String,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ProofResponse)]
    Proof { multisig_session_id: Uint64 },

    #[returns(bool)]
    VerifySignature {
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    },

    #[returns(multisig::verifier_set::VerifierSet)]
    VerifierSet,

    #[returns(Option<u64>)]
    MultisigSessionId { message_id: CrossChainId },
}

#[cw_serde]
#[serde(tag = "status")]
pub enum ProofResponse {
    Completed {
        unsigned_tx_hash: TxHash,
        tx_blob: HexBinary,
    },
    Pending {
        unsigned_tx_hash: TxHash,
    },
}

#[cw_serde]
pub enum ExecuteMsg {
    ConstructProof {
        message_id: CrossChainId,
        payload: HexBinary,
    },
    UpdateTxStatus {
        multisig_session_id: Uint64,
        signer_public_keys: Vec<PublicKey>,
        message_id: TxHash,
        message_status: VerificationStatus,
    },
    UpdateVerifierSet,
    TicketCreate,
    // TODO: only admin
    TrustSet {
        xrpl_token: XRPLToken,
    },
    UpdateSigningThreshold {
        new_signing_threshold: MajorityThreshold,
    },
}

#[cw_serde]
pub struct MigrateMsg {
    pub admin_address: String,
    pub axelar_multisig_address: String,
    pub gateway_address: String,
    pub signing_threshold: MajorityThreshold,
    pub xrpl_multisig_address: String,
    pub voting_verifier_address: String,
    pub service_registry_address: String,
    pub coordinator_address: String,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub xrpl_fee: u64,
    pub ticket_count_threshold: u32,
    pub available_tickets: Vec<u32>,
    pub next_sequence_number: u32,
    pub last_assigned_ticket_number: u32,
    pub governance_address: String,
}
