use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Uint64;
use router_api::{ChainName, CrossChainId};

#[derive(IntoEvent)]
pub enum Event {
    ProofUnderConstruction {
        destination_chain: ChainName,
        unsigned_tx_hash: HexTxHash,
        multisig_session_id: Uint64,
        message_ids: Option<Vec<CrossChainId>>,
    },
    ExecutionDisabled,
    ExecutionEnabled,
}
