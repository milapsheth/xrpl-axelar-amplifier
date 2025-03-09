use axelar_wasm_std::msg_id::HexTxHash;
use cosmwasm_std::Storage;
use router_api::CrossChainId;
use xrpl_types::types::{
    XRPLAccountId, XRPLCrossCurrencyOptions, XRPLPaymentAmount, XRPLPaymentTx, XRPLSequence,
    XRPLSignerEntry, XRPLSignerListSetTx, XRPLTicketCreateTx, XRPLToken, XRPLTrustSetTx,
    XRPLTxStatus, XRPLUnsignedTx,
};

use crate::axelar_verifiers::VerifierSet;
use crate::error::ContractError;
use crate::state::{
    Config, TxInfo, AVAILABLE_TICKETS, CONSUMED_TICKET_TO_UNSIGNED_TX_HASH,
    CROSS_CHAIN_ID_TO_TICKET, CURRENT_VERIFIER_SET, LAST_ASSIGNED_TICKET_NUMBER,
    LATEST_SEQUENTIAL_UNSIGNED_TX_HASH, NEXT_SEQUENCE_NUMBER, NEXT_VERIFIER_SET, TRUST_LINE,
    UNSIGNED_TX_HASH_TO_TX_INFO,
};

const MAX_TICKET_COUNT: u32 = 250;

fn issue_tx(
    storage: &mut dyn Storage,
    unsigned_tx: XRPLUnsignedTx,
    original_cc_id: Option<&CrossChainId>,
) -> Result<HexTxHash, ContractError> {
    let unsigned_tx_hash = xrpl_types::types::hash_unsigned_tx(&unsigned_tx)?;

    let tx_info = TxInfo {
        status: XRPLTxStatus::Pending,
        unsigned_tx: unsigned_tx.clone(),
        original_cc_id: original_cc_id.cloned(),
    };

    UNSIGNED_TX_HASH_TO_TX_INFO.save(storage, &unsigned_tx_hash.tx_hash, &tx_info)?;

    if unsigned_tx.is_sequential() {
        LATEST_SEQUENTIAL_UNSIGNED_TX_HASH.save(storage, &unsigned_tx_hash.tx_hash)?;
    }

    Ok(unsigned_tx_hash)
}

pub fn issue_payment(
    storage: &mut dyn Storage,
    config: &Config,
    destination: XRPLAccountId,
    amount: &XRPLPaymentAmount,
    cc_id: &CrossChainId,
    cross_currency: Option<&XRPLCrossCurrencyOptions>,
) -> Result<HexTxHash, ContractError> {
    let sequence = XRPLSequence::Ticket(assign_ticket_number(storage, cc_id)?);

    let tx = XRPLPaymentTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence,
        amount: amount.clone(),
        destination,
        cross_currency: cross_currency.cloned(),
    };

    issue_tx(storage, XRPLUnsignedTx::Payment(tx), Some(cc_id))
}

pub fn issue_ticket_create(
    storage: &mut dyn Storage,
    config: &Config,
    ticket_count: u32,
) -> Result<HexTxHash, ContractError> {
    let sequence_number = next_sequence_number(storage)?;

    let tx = XRPLTicketCreateTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        ticket_count,
    };

    issue_tx(storage, XRPLUnsignedTx::TicketCreate(tx), None)
}

pub fn issue_trust_set(
    storage: &mut dyn Storage,
    config: &Config,
    xrpl_token: XRPLToken,
) -> Result<HexTxHash, ContractError> {
    let sequence_number = next_sequence_number(storage)?;

    let tx = XRPLTrustSetTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        token: xrpl_token,
    };

    issue_tx(storage, XRPLUnsignedTx::TrustSet(tx), None)
}

pub fn issue_signer_list_set(
    storage: &mut dyn Storage,
    config: &Config,
    verifier_set: VerifierSet,
) -> Result<HexTxHash, ContractError> {
    let sequence_number = next_sequence_number(storage)?;

    let tx = XRPLSignerListSetTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        signer_quorum: verifier_set.quorum,
        signer_entries: verifier_set
            .signers
            .into_iter()
            .map(XRPLSignerEntry::from)
            .collect(),
    };

    issue_tx(storage, XRPLUnsignedTx::SignerListSet(tx), None)
}

// Returns the new verifier set, if it was affected.
pub fn confirm_prover_message(
    storage: &mut dyn Storage,
    unsigned_tx_hash: HexTxHash,
    new_status: XRPLTxStatus,
) -> Result<Option<VerifierSet>, ContractError> {
    let mut tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash.tx_hash)?;
    if tx_info.status != XRPLTxStatus::Pending {
        return Err(ContractError::TxStatusAlreadyConfirmed);
    }

    if new_status == XRPLTxStatus::Pending || new_status == XRPLTxStatus::Inconclusive {
        return Err(ContractError::InvalidTxStatus(new_status));
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number = u32::from(tx_info.unsigned_tx.sequence());
    let sequence_number_increment = tx_info
        .unsigned_tx
        .sequence_number_increment(new_status.clone())?;

    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(
            storage,
            &(tx_sequence_number
                .checked_add(sequence_number_increment)
                .ok_or(ContractError::Overflow)?),
        )?;
    }

    if new_status == XRPLTxStatus::Succeeded || new_status == XRPLTxStatus::FailedOnChain {
        CONSUMED_TICKET_TO_UNSIGNED_TX_HASH.save(
            storage,
            &tx_sequence_number,
            &unsigned_tx_hash.tx_hash,
        )?;
        mark_ticket_unavailable(storage, tx_sequence_number)?;
    }

    UNSIGNED_TX_HASH_TO_TX_INFO.save(storage, &unsigned_tx_hash.tx_hash, &tx_info)?;

    if new_status != XRPLTxStatus::Succeeded {
        return Ok(None);
    }

    Ok(match &tx_info.unsigned_tx {
        XRPLUnsignedTx::TicketCreate(tx) => {
            mark_tickets_available(
                storage,
                tx_sequence_number
                    .checked_add(1)
                    .ok_or(ContractError::Overflow)?
                    ..tx_sequence_number
                        .checked_add(tx.ticket_count)
                        .and_then(|sum| sum.checked_add(1))
                        .ok_or(ContractError::Overflow)?,
            )?;
            None
        }
        XRPLUnsignedTx::SignerListSet(tx) => {
            let next_verifier_set = NEXT_VERIFIER_SET
                .may_load(storage)?
                .ok_or(ContractError::NoVerifierSetToConfirm)?;

            let signer_entries: Vec<XRPLSignerEntry> = next_verifier_set
                .clone()
                .signers
                .into_iter()
                .map(XRPLSignerEntry::from)
                .collect();

            // Sanity check.
            if signer_entries != tx.signer_entries || tx.signer_quorum != next_verifier_set.quorum {
                return Err(ContractError::SignerListMismatch);
            }

            CURRENT_VERIFIER_SET.save(storage, &next_verifier_set)?;
            NEXT_VERIFIER_SET.remove(storage);

            Some(next_verifier_set)
        }
        XRPLUnsignedTx::Payment(_) => {
            if tx_info.original_cc_id.is_none() {
                return Err(ContractError::PaymentMissingCrossChainId);
            }

            None
        }
        XRPLUnsignedTx::TrustSet(tx) => {
            TRUST_LINE.save(storage, &tx.token, &())?;
            None
        }
    })
}

// TICKET / SEQUENCE NUMBER ASSIGNEMENT LOGIC

// A message ID can be ticketed a different ticket number
// only if the previous ticket number has been consumed
// by a TX that doesn't correspond to this message.
fn assign_ticket_number(
    storage: &mut dyn Storage,
    cc_id: &CrossChainId,
) -> Result<u32, ContractError> {
    // If this message ID has already been ticketed,
    // then use the same ticket number as before,
    if let Some(ticket_number) = CROSS_CHAIN_ID_TO_TICKET.may_load(storage, cc_id)? {
        let confirmed_unsigned_tx_hash =
            CONSUMED_TICKET_TO_UNSIGNED_TX_HASH.may_load(storage, &ticket_number)?;
        // as long as it has not already been consumed
        if confirmed_unsigned_tx_hash.is_none()
        // or if it has been consumed by the same message.
        || UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &confirmed_unsigned_tx_hash.unwrap())?.original_cc_id.as_ref() == Some(cc_id)
        {
            return Ok(ticket_number);
        }
    }

    // Otherwise, use the next available ticket number.
    let new_ticket_number = next_ticket_number(storage)?;
    CROSS_CHAIN_ID_TO_TICKET.save(storage, cc_id, &new_ticket_number)?;
    Ok(new_ticket_number)
}

fn next_ticket_number(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    if let Some(first_ticket_number) = available_tickets.first() {
        // find next largest in available, otherwise re-use available_tickets[0]
        let ticket_number = available_tickets
            .iter()
            .find(|&x| x > &last_assigned_ticket_number)
            .unwrap_or(first_ticket_number);

        LAST_ASSIGNED_TICKET_NUMBER.save(storage, ticket_number)?;

        Ok(*ticket_number)
    } else {
        Err(ContractError::NoAvailableTickets)
    }
}

pub fn num_of_tickets_to_create(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let available_ticket_count =
        u32::try_from(available_tickets.len()).map_err(|_| ContractError::TooManyAvailableTickets)?;

    if available_ticket_count > MAX_TICKET_COUNT {
        return Err(ContractError::TooManyAvailableTickets);
    }

    MAX_TICKET_COUNT
        .checked_sub(available_ticket_count)
        .ok_or(ContractError::Overflow)
}

fn next_sequence_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    match load_latest_sequential_tx_info(storage)? {
        Some(latest_sequential_tx_info)
            if latest_sequential_tx_info.status == XRPLTxStatus::Pending =>
        // this might still be pending but another tx with same sequence number may be confirmed!!!
        {
            Ok(latest_sequential_tx_info.unsigned_tx.sequence().into())
        }
        _ => NEXT_SEQUENCE_NUMBER.load(storage).map_err(|e| e.into()),
    }
}

fn load_latest_sequential_tx_info(storage: &dyn Storage) -> Result<Option<TxInfo>, ContractError> {
    LATEST_SEQUENTIAL_UNSIGNED_TX_HASH
        .may_load(storage)?
        .map_or(Ok(None), |tx_hash| {
            Ok(UNSIGNED_TX_HASH_TO_TX_INFO.may_load(storage, &tx_hash)?)
        })
}

fn mark_tickets_available(
    storage: &mut dyn Storage,
    tickets: impl Iterator<Item = u32>,
) -> Result<(), ContractError> {
    let mut available_tickets = AVAILABLE_TICKETS.load(storage)?;
    available_tickets.extend(tickets);

    if available_tickets.len() > MAX_TICKET_COUNT as usize {
        return Err(ContractError::TooManyAvailableTickets);
    }

    Ok(AVAILABLE_TICKETS.save(storage, &available_tickets)?)
}

fn mark_ticket_unavailable(storage: &mut dyn Storage, ticket: u32) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |mut available_tickets| -> Result<_, ContractError> {
        available_tickets.retain(|&x| x != ticket);
        Ok(available_tickets)
    })?;
    Ok(())
}
