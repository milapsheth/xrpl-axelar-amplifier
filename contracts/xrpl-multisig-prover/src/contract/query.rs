use router_api::CrossChainId;
use cosmwasm_std::{HexBinary, StdResult, Storage, Uint64};

use multisig::key::PublicKey;
use multisig::{key::Signature, types::MultisigState};
use xrpl_types::error::XRPLError;

use crate::state::{MultisigSession, AVAILABLE_TICKETS, CROSS_CHAIN_ID_TO_MULTISIG_SESSION, CROSS_CHAIN_ID_TO_TICKET, NEXT_VERIFIER_SET};
use crate::{
    error::ContractError,
    msg::ProofResponse,
    querier::Querier,
    state::{CURRENT_VERIFIER_SET, MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH, UNSIGNED_TX_HASH_TO_TX_INFO},
    xrpl_serialize::XRPLSerialize,
};
use xrpl_types::types::*;

fn message_to_sign(
    storage: &dyn Storage,
    multisig_session_id: &Uint64,
    signer_xrpl_address: &XRPLAccountId,
) -> Result<[u8; 32], ContractError> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TxStatusNotPending.into());
    }

    let encoded_unsigned_tx = tx_info.unsigned_contents.xrpl_serialize()?;
    Ok(xrpl_types::types::message_to_sign(encoded_unsigned_tx, signer_xrpl_address)?)
}

pub fn verify_signature(
    storage: &dyn Storage,
    multisig_session_id: &Uint64,
    public_key: &PublicKey,
    signature: &Signature,
) -> StdResult<bool> {
    let signer_xrpl_address = XRPLAccountId::from(public_key);
    let tx_hash = message_to_sign(storage, multisig_session_id, &signer_xrpl_address)?;
    Ok(signature
        .verify(HexBinary::from(tx_hash), public_key)
        .is_ok())
}

pub fn proof(
    storage: &dyn Storage,
    querier: Querier,
    multisig_session_id: &Uint64,
) -> StdResult<ProofResponse> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;

    let multisig_session = querier.multisig(multisig_session_id)?;

    let response = match multisig_session.state {
        MultisigState::Pending => ProofResponse::Pending { unsigned_tx_hash },
        MultisigState::Completed { .. } => {
            let xrpl_signers: Vec<XRPLSigner> = multisig_session
                .verifier_set
                .signers
                .into_iter()
                .filter_map(|(signer_address, signer)| multisig_session.signatures.get(&signer_address).cloned().zip(Some(signer)))
                .map(XRPLSigner::try_from)
                .collect::<Result<Vec<_>, XRPLError>>()?;
            let signed_tx = XRPLSignedTransaction::new(tx_info.unsigned_contents, xrpl_signers);
            let tx_blob: HexBinary = HexBinary::from(signed_tx.xrpl_serialize()?);
            ProofResponse::Completed {
                unsigned_tx_hash,
                tx_blob,
            }
        }
    };

    Ok(response)
}

pub fn current_verifier_set(store: &dyn Storage) -> StdResult<Option<multisig::verifier_set::VerifierSet>> {
    CURRENT_VERIFIER_SET
        .may_load(store)
        .map(|op| op.map(|set| set.into()))
}

pub fn next_verifier_set(store: &dyn Storage) -> StdResult<Option<multisig::verifier_set::VerifierSet>> {
    NEXT_VERIFIER_SET
        .may_load(store)
        .map(|op| op.map(|set| set.into()))
}

pub fn multisig_session(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> StdResult<Option<MultisigSession>> {
    let existing_ticket_number = CROSS_CHAIN_ID_TO_TICKET.may_load(storage, cc_id)?;
    let available_tickets = AVAILABLE_TICKETS.may_load(storage)?;
    if existing_ticket_number.is_none() || available_tickets.is_none() {
        return Ok(None);
    }

    if available_tickets
        .unwrap()
        .contains(&existing_ticket_number.unwrap())
    {
        return CROSS_CHAIN_ID_TO_MULTISIG_SESSION.may_load(storage, cc_id);
    }

    Ok(None)
}
