use std::collections::HashSet;

use axelar_wasm_std::{address, nonempty, permission_control, FnExt, VerificationStatus, MajorityThreshold};
use interchain_token_service::HubMessage;
use router_api::CrossChainId;
use cosmwasm_std::{wasm_execute, Addr, DepsMut, Env, HexBinary, Response, Storage, SubMsg, Uint256, Uint64};
use multisig::{key::PublicKey, types::MultisigState};
use sha3::{Keccak256, Digest};
use xrpl_types::error::XRPLError;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{
    canonicalize_token_amount, XRP_DECIMALS, XRP_MAX_UINT,
    TxHash, XRPLToken, XRPLSigner, XRPLSignedTx, XRPLPaymentAmount, XRPLAccountId,
    XRPLTokenOrXrp
};

use crate::axelar_verifiers;
use crate::error::ContractError;
use crate::querier::Querier;
use crate::state::{self, Config};
use crate::xrpl_multisig;
use crate::xrpl_serialize::XRPLSerialize;

use super::START_MULTISIG_REPLY_ID;

pub fn construct_trust_set_proof(
    storage: &mut dyn Storage,
    querier: &Querier,
    self_address: Addr,
    config: &Config,
    xrpl_token: XRPLToken,
) -> Result<Response, ContractError> {
    if !xrpl_token.is_local(config.xrpl_multisig.clone()) {
        return Err(ContractError::TokenNotLocal(xrpl_token));
    }

    if querier.xrpl_token(XRPLTokenOrXrp::Issued(xrpl_token.clone()).token_id())? != xrpl_token {
        return Err(ContractError::LocalTokenNotRegistered(xrpl_token));
    }

    // TODO: Check if trust line already exists.
    let unsigned_tx_hash = xrpl_multisig::issue_trust_set(storage, config, xrpl_token)?;
    Ok(Response::new().add_submessage(start_signing_session(storage, config, unsigned_tx_hash, self_address, None)?))
}

pub fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::num_of_tickets_to_create(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached);
    }

    let unsigned_tx_hash = xrpl_multisig::issue_ticket_create(storage, config, ticket_count)?;
    Ok(Response::new().add_submessage(start_signing_session(storage, config, unsigned_tx_hash, self_address, None)?))
}

pub fn confirm_tx_status(
    storage: &mut dyn Storage,
    querier: &Querier,
    config: &Config,
    multisig_session_id: &Uint64,
    signer_public_keys: &[PublicKey],
    tx_id: TxHash,
) -> Result<Response, ContractError> {
    let num_signer_public_keys = signer_public_keys.len();
    if num_signer_public_keys == 0 {
        return Err(ContractError::EmptySignerPublicKeys);
    }

    let unsigned_tx_hash =
        state::MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.load(storage, multisig_session_id.u64())?;
    let mut tx_info = state::UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;
    let multisig_session = querier.multisig(multisig_session_id)?;

    let xrpl_signers: Vec<XRPLSigner> = multisig_session
        .verifier_set
        .signers
        .into_iter()
        .filter(|(_, signer)| signer_public_keys.contains(&signer.pub_key))
        .filter_map(|(signer_address, signer)| multisig_session.signatures.get(&signer_address).cloned().zip(Some(signer)))
        .map(XRPLSigner::try_from)
        .collect::<Result<Vec<XRPLSigner>, XRPLError>>()?;

    if xrpl_signers.len() != num_signer_public_keys {
        return Err(ContractError::InvalidSignerPublicKeys);
    }

    let signed_tx = XRPLSignedTx::new(tx_info.unsigned_tx.clone(), xrpl_signers);
    let signed_tx_hash = xrpl_types::types::hash_signed_tx(
        HexBinary::from(signed_tx.xrpl_serialize()?).as_slice(),
    )?;

    if tx_id != signed_tx_hash {
        return Err(ContractError::InvalidTxId(tx_id));
    }

    let message = XRPLMessage::ProverMessage(tx_id);
    let status = querier.message_status(message)?;

    match status {
        VerificationStatus::Unknown |
        VerificationStatus::FailedToVerify => {
            return Err(ContractError::TxStatusUnknown);
        },
        VerificationStatus::InProgress => {
            return Err(ContractError::TxStatusVerificationInProgress);
        },
        _ => {}
    }

    Ok(match xrpl_multisig::confirm_tx_status(storage, unsigned_tx_hash, &mut tx_info, status.into())? {
        None => Response::default(),
        Some(confirmed_verifier_set) => {
            Response::new()
                .add_message(wasm_execute(
                    config.multisig.clone(),
                    &multisig::msg::ExecuteMsg::RegisterVerifierSet {
                        verifier_set: confirmed_verifier_set.clone().into(),
                    },
                    vec![],
                )?)
                .add_message(wasm_execute(
                    config.coordinator.clone(),
                    &coordinator::msg::ExecuteMsg::SetActiveVerifiers {
                        verifiers: confirmed_verifier_set
                            .signers
                            .iter()
                            .map(|signer| signer.address.to_string())
                            .collect::<HashSet<String>>(),
                    },
                    vec![],
                )?)
        }
    })
}

fn save_next_verifier_set(
    storage: &mut dyn Storage,
    new_verifier_set: &axelar_verifiers::VerifierSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, new_verifier_set) {
        return Err(ContractError::VerifierSetConfirmationInProgress);
    }

    state::NEXT_VERIFIER_SET.save(storage, new_verifier_set)?;
    Ok(())
}

// Returns true if there is a different verifier set pending for confirmation, false if there is no
// verifier set pending or if the pending set is the same
fn different_set_in_progress(storage: &dyn Storage, new_verifier_set: &axelar_verifiers::VerifierSet) -> bool {
    if let Ok(Some(next_verifier_set)) = state::NEXT_VERIFIER_SET.may_load(storage) {
        return next_verifier_set != *new_verifier_set;
    }

    false
}

pub fn update_signing_threshold(
    deps: DepsMut,
    new_signing_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    state::CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.signing_threshold = new_signing_threshold;
            Ok(config)
        },
    )?;
    Ok(Response::new())
}

pub fn update_admin(deps: DepsMut, new_admin_address: String) -> Result<Response, ContractError> {
    let new_admin = address::validate_cosmwasm_address(deps.api, &new_admin_address)
        .map_err(|_| ContractError::FailedToUpdateAdmin)?;
    permission_control::set_admin(deps.storage, &new_admin)
        .map_err(|_| ContractError::FailedToUpdateAdmin)?;
    Ok(Response::new())
}

fn convert_scaled_uint256_to_drops(value: Uint256) -> Result<u64, ContractError> {
    if value.gt(&XRP_MAX_UINT.into()) {
        return Err(ContractError::Overflow);
    }

    let mut last_8 = [0u8; 8];
    last_8.copy_from_slice(&value.to_be_bytes()[24..32]);
    Ok(u64::from_be_bytes(last_8))
}

// Converts the given amount of tokens to XRP drops.
fn scale_to_drops(
    source_amount: nonempty::Uint256,
    source_decimals: u8,
) -> Result<u64, ContractError> {
    assert!(source_decimals <= 82);

    if source_decimals == XRP_DECIMALS {
        return convert_scaled_uint256_to_drops(source_amount.into());
    }

    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(source_decimals.abs_diff(XRP_DECIMALS).into())
        .expect("exponent cannot be too large");

    let destination_amount = if source_decimals > XRP_DECIMALS {
        Ok(source_amount
            .checked_div(scaling_factor)
            .expect("scaling factor must be non-zero"))
    } else {
        source_amount
            .checked_mul(scaling_factor)
            .map_err(|_| ContractError::Overflow)
    }?;

    convert_scaled_uint256_to_drops(destination_amount)
}

pub fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: &Querier,
    self_address: Addr,
    block_height: u64,
    config: &Config,
    cc_id: CrossChainId, // TODO: Optimize: Source chain is always axelar.
    payload: HexBinary,
) -> Result<Response, ContractError> {
    // Prevent creating a duplicate signing session before the previous one expires
    if let Some(multisig_session) =
        state::CROSS_CHAIN_ID_TO_MULTISIG_SESSION.may_load(storage, &cc_id)?
    {
        match querier.multisig(&Uint64::from(multisig_session.id))?.state {
            MultisigState::Pending => {
                if multisig_session.expires_at <= block_height {
                    return Err(ContractError::PaymentAlreadyHasActiveSigningSession(
                        multisig_session.id,
                    ));
                }
            }
            MultisigState::Completed { .. } => {
                // TODO: Don't throw error in this case to allow retries.
                return Err(ContractError::PaymentAlreadyHasCompletedSigningSession(
                    multisig_session.id
                ));
            }
        }
    };

    let message = querier.outgoing_message(&cc_id)?;

    // Message source chain (Axelar) and source address (ITS hub) has been validated by the gateway.
    // TODO: Check with Axelar if this destination chain check is necessary.
    if message.destination_chain != config.chain_name {
        return Err(ContractError::InvalidDestinationChain {
            expected: config.chain_name.clone(),
            actual: message.destination_chain,
        });
    }

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    if message.payload_hash != payload_hash {
        return Err(ContractError::PayloadHashMismatch {
            expected: message.payload_hash,
            actual: payload_hash,
        });
    }

    let its_hub_message = HubMessage::abi_decode(payload.as_slice()).map_err(|_| ContractError::InvalidPayload)?;
    match its_hub_message {
        HubMessage::SendToHub { .. } => {
            Err(ContractError::InvalidPayload)
        },
        HubMessage::ReceiveFromHub { source_chain, message } => {
            match message {
                // Source address (ITS on source chain) has been validated by ITS hub.
                interchain_token_service::Message::InterchainTransfer { token_id, source_address: _, destination_address, amount: source_amount, data: _ } => {
                    // TODO: Consider enforcing that data is None for simple payments.
                    let destination_address = XRPLAccountId::try_from(destination_address)
                        .map_err(|_| ContractError::InvalidDestinationAddress)?;

                    let source_decimals = querier.token_instance_decimals(source_chain.clone(), token_id.clone())
                        .map_err(|_| ContractError::TokenNotRegisteredForChain {
                            token_id: token_id.to_owned(),
                            chain_name: source_chain.to_owned(),
                        })?;

                    let is_xrp = token_id == XRPLTokenOrXrp::Xrp.token_id(); // TODO: Optimize: Don't compute hash every time.
                    let xrpl_payment_amount = if is_xrp {
                        let drops = scale_to_drops(source_amount, source_decimals)
                            .map_err(|_| ContractError::InvalidTransferAmount {
                                source_chain: source_chain.to_owned(),
                                amount: source_amount.into(),
                            })?;

                        XRPLPaymentAmount::Drops(drops)
                    } else {
                        let xrpl_token = querier.xrpl_token(token_id)?;
                        let xrpl_token_amount = canonicalize_token_amount(source_amount.into(), source_decimals)
                            .map_err(|_| ContractError::InvalidTransferAmount {
                                source_chain: source_chain.to_owned(),
                                amount: source_amount.into(),
                            })?;

                        XRPLPaymentAmount::Issued(xrpl_token, xrpl_token_amount)
                    };

                    let unsigned_tx_hash = xrpl_multisig::issue_payment(
                        storage,
                        config,
                        destination_address,
                        &xrpl_payment_amount,
                        &cc_id,
                        None // TODO: Handle cross-currency payments.
                    )?;

                    state::REPLY_CROSS_CHAIN_ID.save(storage, &cc_id)?;
                    Ok(Response::new().add_submessage(start_signing_session(storage, config, unsigned_tx_hash, self_address, None)?))
                },
                interchain_token_service::Message::DeployInterchainToken { .. } => {
                    Err(ContractError::InvalidPayload)
                },
                interchain_token_service::Message::DeployTokenManager { .. } => {
                    Err(ContractError::InvalidPayload)
                },
            }
        }
    }
}

fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    unsigned_tx_hash: TxHash,
    self_address: Addr,
    verifier_set_id: Option<String>,
) -> Result<SubMsg<cosmwasm_std::Empty>, ContractError> {
    state::REPLY_UNSIGNED_TX_HASH.save(storage, &unsigned_tx_hash)?;

    let verifier_set_id = match verifier_set_id {
        Some(id) => id,
        None => {
            let cur_verifier_set = state::CURRENT_VERIFIER_SET
                .load(storage)
                .map_err(|_| ContractError::NoVerifierSet)?;
            Into::<multisig::verifier_set::VerifierSet>::into(cur_verifier_set).id()
        },
    };

    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        verifier_set_id,
        msg: unsigned_tx_hash.into(),
        chain_name: config.chain_name.clone(),
        sig_verifier: Some(self_address.into()),
    };

    let wasm_msg = wasm_execute(&config.multisig, &start_sig_msg, vec![])?;

    Ok(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID))
}

pub fn update_verifier_set(
    storage: &mut dyn Storage,
    querier: &Querier,
    env: Env,
) -> Result<Response, ContractError> {
    let config = state::CONFIG.load(storage).map_err(ContractError::from)?;
    let cur_verifier_set = state::CURRENT_VERIFIER_SET
        .may_load(storage)
        .map_err(ContractError::from)?;

    match cur_verifier_set {
        None => {
            // if no verifier set, just store it and return
            let new_verifier_set = axelar_verifiers::active_verifiers(querier, config.signing_threshold, env.block.height)?;
            state::CURRENT_VERIFIER_SET
                .save(storage, &new_verifier_set)
                .map_err(ContractError::from)?;

            Ok(Response::new().add_message(
                wasm_execute(
                    config.multisig,
                    &multisig::msg::ExecuteMsg::RegisterVerifierSet {
                        verifier_set: new_verifier_set.into(),
                    },
                    vec![],
                )
                .map_err(ContractError::from)?,
            ))
        }
        Some(cur_verifier_set) => {
            let new_verifier_set = next_verifier_set(storage, querier, &env, &config)?
                .ok_or(ContractError::VerifierSetUnchanged)?;

            save_next_verifier_set(storage, &new_verifier_set)?;

            let verifier_union_set = all_active_verifiers(storage)?;
            let unsigned_tx_hash = xrpl_multisig::issue_signer_list_set(storage, &config, new_verifier_set.clone())?;

            Ok(Response::new()
                .add_submessage(
                    start_signing_session(
                        storage,
                        &config,
                        unsigned_tx_hash,
                        env.contract.address,
                        Some(multisig::verifier_set::VerifierSet::from(cur_verifier_set).id()),
                    )?
                )
                .add_message(
                    wasm_execute(
                        config.coordinator,
                        &coordinator::msg::ExecuteMsg::SetActiveVerifiers {
                            verifiers: verifier_union_set,
                        },
                        vec![],
                    )
                    .map_err(ContractError::from)?,
                ))
        }
    }
}

fn all_active_verifiers(storage: &mut dyn Storage) -> Result<HashSet<String>, ContractError> {
    let current_signers = state::CURRENT_VERIFIER_SET
        .may_load(storage)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    let next_signers = state::NEXT_VERIFIER_SET
        .may_load(storage)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    current_signers
        .iter()
        .chain(next_signers.iter())
        .map(|signer| signer.address.to_string())
        .collect::<HashSet<String>>()
        .then(Ok)
}

fn next_verifier_set(
    storage: &mut dyn Storage,
    querier: &Querier,
    env: &Env,
    config: &Config,
) -> Result<Option<axelar_verifiers::VerifierSet>, ContractError> {
    // if there's already a pending verifiers set update, just return it
    if let Some(pending_verifier_set) = state::NEXT_VERIFIER_SET.may_load(storage)? {
        return Ok(Some(pending_verifier_set));
    }
    let cur_verifier_set = state::CURRENT_VERIFIER_SET.may_load(storage)?;
    let new_verifier_set = axelar_verifiers::active_verifiers(querier, config.signing_threshold, env.block.height)?;

    match cur_verifier_set {
        Some(cur_verifier_set) => {
            if axelar_verifiers::should_update_verifier_set(
                &new_verifier_set.clone().into(),
                &cur_verifier_set.into(),
                config.verifier_set_diff_threshold as usize,
            ) {
                Ok(Some(new_verifier_set))
            } else {
                Ok(None)
            }
        }
        None => Err(ContractError::NoVerifierSet),
    }
}
