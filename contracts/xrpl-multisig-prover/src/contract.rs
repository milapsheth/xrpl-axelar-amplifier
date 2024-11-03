use std::collections::HashSet;
use std::str::FromStr;

use axelar_wasm_std::{permission_control, FnExt};
use axelar_wasm_std::{MajorityThreshold, VerificationStatus};
use interchain_token_service as its;
use router_api::{ChainNameRaw, CrossChainId};
use cosmwasm_std::{
    entry_point, to_json_binary, wasm_execute, Addr, Binary, Deps, DepsMut, Env, Fraction, HexBinary, MessageInfo, Reply, Response, StdResult, Storage, SubMsg, Uint128, Uint256, Uint64
};

use multisig::{key::PublicKey, types::MultisigState};
use sha3::{Keccak256, Digest};
use xrpl_types::error::XRPLError;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::*;

use crate::msg::MigrateMsg;
use crate::{
    axelar_workers::{self, VerifierSet},
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    querier::Querier,
    query, reply,
    state::{
        Config, AVAILABLE_TICKETS, CONFIG, CURRENT_VERIFIER_SET, LAST_ASSIGNED_TICKET_NUMBER,
        MESSAGE_ID_TO_MULTISIG_SESSION, MULTISIG_SESSION_ID_TO_TX_HASH, NEXT_SEQUENCE_NUMBER,
        NEXT_VERIFIER_SET, REPLY_MESSAGE_ID, REPLY_TX_HASH, TRANSACTION_INFO,
    },
    types::*,
    xrpl_multisig,
    xrpl_serialize::XRPLSerialize,
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = make_config(&deps, msg.clone())?;
    CONFIG.save(deps.storage, &config)?;

    permission_control::set_admin(deps.storage, &deps.api.addr_validate(&msg.admin_address)?)?;
    permission_control::set_governance(
        deps.storage,
        &deps.api.addr_validate(&msg.governance_address)?,
    )?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;

    Ok(Response::default())
}

fn make_config(
    deps: &DepsMut,
    msg: InstantiateMsg,
) -> Result<Config, axelar_wasm_std::error::ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let axelar_multisig = deps.api.addr_validate(&msg.axelar_multisig_address)?;
    let coordinator = deps.api.addr_validate(&msg.coordinator_address)?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;

    if msg.signing_threshold.numerator() > u32::MAX.into()
        || msg.signing_threshold.denominator() == Uint64::zero()
    {
        return Err(ContractError::InvalidSigningThreshold.into());
    }

    Ok(Config {
        admin,
        governance,
        axelar_multisig,
        coordinator,
        gateway,
        xrpl_multisig: msg.xrpl_multisig_address,
        signing_threshold: msg.signing_threshold,
        voting_verifier,
        service_registry,
        service_name: msg.service_name,
        chain_name: msg.chain_name,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
        key_type: multisig::key::KeyType::Ecdsa,
    })
}

pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.admin {
        admin if admin == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.governance {
        governance if governance == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn update_signing_threshold(
    deps: DepsMut,
    new_signing_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.signing_threshold = new_signing_threshold;
            Ok(config)
        },
    )?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let querier = Querier::new(deps.querier, config.clone());

    Ok(match msg {
        // TODO: only admin
        ExecuteMsg::TrustSet { xrpl_token } => {
            construct_trust_set_proof(
                deps.storage,
                env.contract.address,
                &config,
                xrpl_token,
            )
        }
        ExecuteMsg::ConstructProof { message_id, payload } => {
            construct_payment_proof(
                deps.storage,
                &querier,
                env.contract.address,
                env.block.height,
                &config,
                message_id,
                payload,
            )
        }
        ExecuteMsg::UpdateVerifierSet {} => {
            require_admin(&deps, info.clone()).or_else(|_| require_governance(&deps, info))?;
            update_verifier_set(deps.storage, &querier, env)
        }
        ExecuteMsg::UpdateTxStatus {
            multisig_session_id,
            signer_public_keys,
            message_id,
            message_status,
        } => {
            update_tx_status(
                deps.storage,
                &querier,
                &config,
                &multisig_session_id,
                &signer_public_keys,
                &message_id,
                message_status,
            )
        }
        ExecuteMsg::TicketCreate {} => {
            construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        }
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => {
            require_governance(&deps, info)?;
            update_signing_threshold(deps, new_signing_threshold)
        }
    }?)
}

const XRP_DECIMALS: u8 = 6;

// TODO: remove: this conversion is temporary--will be handled by ITS Hub
fn scale_down_to_drops(amount: Uint256, from_decimals: u8) -> u64 {
    assert!(from_decimals > XRP_DECIMALS);
    let scaling_factor = Uint256::from(10u128.pow(u32::from(from_decimals - XRP_DECIMALS)));
    let new_amount = Uint128::try_from(amount / scaling_factor).unwrap();
    u64::try_from(new_amount.u128()).unwrap()
}

fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: &Querier,
    self_address: Addr,
    block_height: u64,
    config: &Config,
    message_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    // Prevent creating a duplicate signing session before the previous one expires
    if let Some(multisig_session) =
        MESSAGE_ID_TO_MULTISIG_SESSION.may_load(storage, &message_id)?
    {
        match querier.get_multisig_session(&Uint64::from(multisig_session.id))?.state {
            MultisigState::Pending => {
                if multisig_session.expires_at <= block_height {
                    return Err(ContractError::PaymentAlreadyHasActiveSigningSession(
                        multisig_session.id,
                    ));
                }
            }
            MultisigState::Completed { .. } => {
                return Err(ContractError::PaymentAlreadyHasCompletedSigningSession(
                    multisig_session.id
                ));
            }
        }
    };

    let message = querier.get_message(&message_id)?;
    if message.payload_hash.as_slice() != Keccak256::digest(payload.clone()).as_slice() {
        return Err(ContractError::InvalidPayload);
    }

    let its_hub_message = its::HubMessage::abi_decode(payload.as_slice()).unwrap();

    match its_hub_message {
        its::HubMessage::SendToHub { .. } => {
            Err(ContractError::InvalidPayload)
        },
        its::HubMessage::ReceiveFromHub { source_chain, message } => {
            match message {
                // TODO: validate source_address?
                interchain_token_service::Message::InterchainTransfer { token_id, source_address, destination_address, amount, data } => {
                    let xrpl_payment_amount = if token_id == XRPLTokenOrXRP::XRP.token_id() { // TODO: don't compute XRP_TOKEN_ID every time
                        let drops = if ChainNameRaw::from_str("xrpl-evm-sidechain").unwrap() == source_chain { // TODO: create XRPL_EVM_SIDECHAIN_NAME const
                            scale_down_to_drops(amount.into(), 18u8)
                        } else {
                            u64::try_from(Uint128::try_from(Uint256::from(amount)).unwrap().u128()).unwrap()
                        };
                        XRPLPaymentAmount::Drops(drops)
                    } else {
                        let token_info = querier.get_token_info(token_id)?;
                        // TODO: handle decimal precision conversion
                        XRPLPaymentAmount::Token(token_info.xrpl_token, canonicalize_coin_amount(Uint128::try_from(Uint256::from(amount)).unwrap(), token_info.canonical_decimals)?)
                    };

                    let destination_bytes: [u8; 20] = destination_address.as_slice().try_into().map_err(|_| ContractError::InvalidAddress)?;
                    let tx_hash = xrpl_multisig::issue_payment(
                        storage,
                        config,
                        XRPLAccountId::from_bytes(destination_bytes),
                        &xrpl_payment_amount,
                        &message_id,
                        None // TODO: how cross-currency payments are specified
                    )?;

                    let cur_verifier_set_id = match CURRENT_VERIFIER_SET.may_load(storage)? {
                        Some(verifier_set) => Into::<multisig::verifier_set::VerifierSet>::into(verifier_set).id(),
                        None => {
                            return Err(ContractError::NoVerifierSet);
                        }
                    };

                    REPLY_MESSAGE_ID.save(storage, &message_id)?;
                    Ok(Response::new().add_submessage(start_signing_session(storage, config, tx_hash, self_address, cur_verifier_set_id)?))
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

pub fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    tx_hash: TxHash,
    self_address: Addr,
    cur_verifier_set_id: String,
) -> Result<SubMsg<cosmwasm_std::Empty>, ContractError> {
    REPLY_TX_HASH.save(storage, &tx_hash)?;

    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        verifier_set_id: cur_verifier_set_id,
        chain_name: config.chain_name.clone(),
        msg: tx_hash.into(),
        sig_verifier: Some(self_address.into()),
    };

    let wasm_msg = wasm_execute(&config.axelar_multisig, &start_sig_msg, vec![])?;

   Ok(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID))
}

fn update_verifier_set(
    storage: &mut dyn Storage,
    querier: &Querier,
    env: Env,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(storage).map_err(ContractError::from)?;
    let cur_verifier_set = CURRENT_VERIFIER_SET
        .may_load(storage)
        .map_err(ContractError::from)?;

    match cur_verifier_set {
        None => {
            // if no verifier set, just store it and return
            let new_verifier_set = axelar_workers::get_active_verifiers(querier, config.signing_threshold, env.block.height)?;
            CURRENT_VERIFIER_SET
                .save(storage, &new_verifier_set)
                .map_err(ContractError::from)?;

            Ok(Response::new().add_message(
                wasm_execute(
                    config.axelar_multisig,
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
            let tx_hash = xrpl_multisig::issue_signer_list_set(storage, &config, new_verifier_set.clone())?;

            Ok(Response::new()
                .add_submessage(
                    start_signing_session(storage, &config, tx_hash, env.contract.address, multisig::verifier_set::VerifierSet::from(cur_verifier_set).id())?
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
    let current_signers = CURRENT_VERIFIER_SET
        .may_load(storage)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    let next_signers = NEXT_VERIFIER_SET
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
) -> Result<Option<VerifierSet>, ContractError> {
    // if there's already a pending verifiers set update, just return it
    if let Some(pending_verifier_set) = NEXT_VERIFIER_SET.may_load(storage)? {
        return Ok(Some(pending_verifier_set));
    }
    let cur_verifier_set = CURRENT_VERIFIER_SET.may_load(storage)?;
    let new_verifier_set = axelar_workers::get_active_verifiers(querier, config.signing_threshold, env.block.height)?;

    match cur_verifier_set {
        Some(cur_verifier_set) => {
            if crate::axelar_workers::should_update_verifier_set(
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

fn save_next_verifier_set(
    storage: &mut dyn Storage,
    new_verifier_set: &VerifierSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, new_verifier_set) {
        return Err(ContractError::VerifierSetConfirmationInProgress);
    }

    NEXT_VERIFIER_SET.save(storage, new_verifier_set)?;
    Ok(())
}

// Returns true if there is a different verifier set pending for confirmation, false if there is no
// verifier set pending or if the pending set is the same
fn different_set_in_progress(storage: &dyn Storage, new_verifier_set: &VerifierSet) -> bool {
    if let Ok(Some(next_verifier_set)) = NEXT_VERIFIER_SET.may_load(storage) {
        return next_verifier_set != *new_verifier_set;
    }

    false
}

fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::tickets_available_to_request(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached);
    }

    let tx_hash = xrpl_multisig::issue_ticket_create(storage, config, ticket_count)?;

    let cur_verifier_set_id = match CURRENT_VERIFIER_SET.may_load(storage)? {
        Some(verifier_set) => Into::<multisig::verifier_set::VerifierSet>::into(verifier_set).id(),
        None => {
            return Err(ContractError::NoVerifierSet);
        }
    };

    Ok(Response::new().add_submessage(start_signing_session(storage, config, tx_hash, self_address, cur_verifier_set_id)?))
}

fn construct_trust_set_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
    xrpl_token: XRPLToken,
) -> Result<Response, ContractError> {
    // TODO: check if trust set already set
    let tx_hash = xrpl_multisig::issue_trust_set(storage, config, xrpl_token)?;

    // TODO: deduplicate from other construct_*_proof functions:
    let verifier_set = CURRENT_VERIFIER_SET.load(storage).map_err(|_| ContractError::NoVerifierSet)?;
    let cur_verifier_set_id = Into::<multisig::verifier_set::VerifierSet>::into(verifier_set).id();

    Ok(Response::new().add_submessage(start_signing_session(storage, config, tx_hash, self_address, cur_verifier_set_id)?))
}

fn update_tx_status(
    storage: &mut dyn Storage,
    querier: &Querier,
    config: &Config,
    multisig_session_id: &Uint64,
    signer_public_keys: &[PublicKey],
    message_id: &TxHash,
    status: VerificationStatus,
) -> Result<Response, ContractError> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_TX_HASH.load(storage, multisig_session_id.u64())?;
    let tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    let multisig_session = querier.get_multisig_session(multisig_session_id)?;

    let xrpl_signers: Vec<XRPLSigner> = multisig_session
        .verifier_set
        .signers
        .into_iter()
        .filter(|(_, signer)| signer_public_keys.contains(&signer.pub_key))
        .filter_map(|(signer_address, signer)| multisig_session.signatures.get(&signer_address).cloned().zip(Some(signer)))
        .map(XRPLSigner::try_from)
        .collect::<Result<Vec<XRPLSigner>, XRPLError>>()?;

    if xrpl_signers.len() != signer_public_keys.len() {
        return Err(ContractError::SignatureNotFound);
    }

    let signed_tx = XRPLSignedTransaction::new(tx_info.unsigned_contents, xrpl_signers);
    let tx_blob = HexBinary::from(signed_tx.xrpl_serialize()?);
    let tx_hash: HexBinary = xrpl_multisig::compute_signed_tx_hash(tx_blob.as_slice())?.into();

    if message_id.0 != tx_hash {
        return Err(ContractError::InvalidMessageID(message_id.0.to_string()));
    }

    let message = XRPLMessage::ProverMessage(message_id.0.to_vec().try_into().unwrap());
    let actual_status = querier.get_message_status(message)?;
    if status != actual_status {
        return Err(ContractError::InvalidMessageStatus);
    }

    let res = match xrpl_multisig::update_tx_status(storage, unsigned_tx_hash, status.into())? {
        None => Response::default(),
        Some(confirmed_verifier_set) => {
            Response::new()
                .add_message(wasm_execute(
                    config.axelar_multisig.clone(),
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
    };

    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let config = CONFIG.load(deps.storage)?;
    let querier = Querier::new(deps.querier, config.clone());
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::get_proof(
            deps.storage,
            querier,
            &multisig_session_id,
        )?),
        QueryMsg::VerifySignature {
            session_id,
            message: _,
            public_key,
            signature,
            signer_address: _,
        } => to_json_binary(&query::verify_signature(
            deps.storage,
            &session_id,
            &PublicKey::Ecdsa(public_key),
            &multisig::key::Signature::try_from((multisig::key::KeyType::Ecdsa, signature))
                .map_err(|_| ContractError::InvalidSignature)?,
        )?),
        QueryMsg::VerifierSet {} => to_json_binary(&query::get_verifier_set(deps.storage)?),
        QueryMsg::MultisigSession { message_id } => {
            to_json_binary(&query::get_multisig_session(deps.storage, &message_id)?)
        } // TODO: rename
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    CONFIG.remove(deps.storage);

    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let axelar_multisig = deps.api.addr_validate(&msg.axelar_multisig_address)?;
    let coordinator = deps.api.addr_validate(&msg.coordinator_address)?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;

    if msg.signing_threshold.numerator() > u32::MAX.into()
        || msg.signing_threshold.denominator() == Uint64::zero()
    {
        return Err(ContractError::InvalidSigningThreshold.into());
    }

    let config = Config {
        admin,
        governance,
        axelar_multisig,
        coordinator,
        gateway,
        xrpl_multisig: msg.xrpl_multisig_address,
        signing_threshold: msg.signing_threshold,
        voting_verifier,
        service_registry,
        service_name: msg.service_name,
        chain_name: msg.chain_name,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        xrpl_fee: msg.xrpl_fee,
        ticket_count_threshold: msg.ticket_count_threshold,
        key_type: multisig::key::KeyType::Ecdsa,
    };

    CONFIG.save(deps.storage, &config)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;

    Ok(Response::default())
}
