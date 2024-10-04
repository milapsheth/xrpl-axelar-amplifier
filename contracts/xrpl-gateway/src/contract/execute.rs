use std::collections::HashMap;
use std::str::FromStr;

use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::{FnExt, VerificationStatus};
use cosmwasm_std::{Addr, Event, HexBinary, Response, Storage, Uint256, WasmMsg};
use error_stack::{report, Result, ResultExt};
use itertools::Itertools;
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};
use xrpl_types::types::{XRPLPaymentAmount, XRPLTokenOrXRP};
use xrpl_voting_verifier::msg::MessageStatus;
use xrpl_types::msg::{CrossChainMessage, XRPLMessage, XRPLMessageWithPayload};
use interchain_token_service::{ItsHubMessage, ItsMessage, TokenId, TokenManagerType};

use crate::contract::Error;
use crate::events::GatewayEvent;
use crate::msg::InterchainTokenDeployment;
use crate::state;

pub fn verify_messages(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<XRPLMessage>,
) -> Result<Response, Error> {
    apply(verifier, msgs, |msgs_by_status| {
        verify(verifier, msgs_by_status)
    })
}

pub(crate) fn route_incoming_messages(
    store: &dyn Storage,
    verifier: &xrpl_voting_verifier::Client,
    router: &Router,
    msgs: Vec<XRPLMessageWithPayload>,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig_address: &String,
) -> Result<Response, Error> {
    let msg_id_to_payload: HashMap<CrossChainId, HexBinary> = msgs.iter().map(|msg| (msg.message.cc_id(), msg.payload.clone())).collect();
    apply(verifier, msgs.into_iter().map(|m| m.message).collect(), |msgs_by_status| {
        let msgs_by_status = msgs_by_status.into_iter().map(|(status, msgs)| {
            let payloads: Vec<HexBinary> = msgs.iter().map(|msg| msg_id_to_payload.get(&msg.cc_id()).unwrap().clone()).collect();
            (status, msgs.into_iter().zip(payloads).map(|(msg, payload)| XRPLMessageWithPayload { message: msg, payload }).collect())
        }).collect();
        route(store, router, msgs_by_status, its_hub, axelar_chain_name, xrpl_multisig_address)
    })
}

// because the messages came from the router, we can assume they are already verified
pub(crate) fn route_outgoing_messages(
    store: &mut dyn Storage,
    verified: Vec<Message>,
    its_hub: Addr,
    axelar_chain_name: ChainName,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified)?;

    for msg in msgs.iter() {
        if msg.source_address.to_string() != its_hub.to_string() {
            return Err(Error::InvalidMessage(msg.cc_id.clone()).into());
        }

        if msg.cc_id.source_chain != axelar_chain_name {
            return Err(Error::InvalidMessage(msg.cc_id.clone()).into())
        }

        state::OUTGOING_MESSAGES
            .may_load(store, &msg.cc_id)
            .change_context(Error::InvalidStoreAccess)
            .and_then(|stored_msg| match stored_msg {
                Some(stored_msg) if msg.hash() != stored_msg.hash() => {
                    Err(report!(Error::MessageMismatch(msg.cc_id.clone())))
                }
                Some(_) => Ok(()), // message already exists
                None => state::OUTGOING_MESSAGES
                    .save(store, &msg.cc_id, msg)
                    .change_context(Error::InvalidStoreAccess),
            })?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::RoutingOutgoing { msg }.into()),
    ))
}

pub(crate) fn deploy_xrp_to_sidechain(
    storage: &mut dyn Storage,
    block_height: u64,
    router: &Router,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_chain_name: &ChainName,
    sidechain_name: &ChainName,
    xrpl_multisig_address: &String,
    params: HexBinary,
) -> Result<Response, Error> {
    let token_id = XRPLTokenOrXRP::XRP.token_id();
    let its_msg = ItsHubMessage::SendToHub {
        destination_chain: sidechain_name.clone(),
        message: ItsMessage::DeployTokenManager {
            token_id,
            token_manager_type: TokenManagerType::LockUnlock,
            params,
        },
    };

    let payload = its_msg.abi_encode();

    let msg = Message {
        cc_id: generate_cross_chain_id(storage, block_height, xrpl_chain_name.clone())?,
        source_address: Address::from_str(&xrpl_multisig_address).unwrap(),
        destination_address: Address::from_str(its_hub.as_str()).unwrap(),
        destination_chain: axelar_chain_name.clone(),
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
    };

    Ok(Response::new().add_messages(router.route(vec![msg.clone()])).add_event(GatewayEvent::RoutingIncoming { msg }.into()))
}

#[test]
fn send_to_hub() {
    let token_id = XRPLTokenOrXRP::XRP.token_id();
    let original = ItsHubMessage::SendToHub {
        destination_chain: ChainName::from_str("xrpl-evm-sidechain").unwrap(),
        message: ItsMessage::DeployTokenManager {
            token_id,
            token_manager_type: TokenManagerType::LockUnlock,
            params: HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000a7baa2fe1df377147aaf49858b399f8c2564e8a400000000000000000000000000000000000000000000000000000000000000140A90c0Af1B07f6AC34f3520348Dbfae73BDa358E000000000000000000000000").unwrap(),
        },
    };

    let encoded = original.clone().abi_encode();
    println!("encoded: {:?}", encoded);
    let decoded = ItsHubMessage::abi_decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn receive_from_hub() {
    let token_id = XRPLTokenOrXRP::XRP.token_id();
    let original = ItsHubMessage::ReceiveFromHub {
        source_chain: ChainName::from_str("xrpl").unwrap().into(),
        message: ItsMessage::DeployTokenManager {
            token_id,
            token_manager_type: TokenManagerType::LockUnlock,
            params: HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000a7baa2fe1df377147aaf49858b399f8c2564e8a400000000000000000000000000000000000000000000000000000000000000140A90c0Af1B07f6AC34f3520348Dbfae73BDa358E000000000000000000000000").unwrap(),
        },
    };

    let encoded = original.clone().abi_encode();
    println!("encoded: {:?}", encoded);
    let decoded = ItsHubMessage::abi_decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

pub(crate) fn deploy_interchain_token(
    storage: &mut dyn Storage,
    block_height: u64,
    router: &Router,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_chain_name: &ChainName,
    xrpl_multisig_address: &String,
    params: InterchainTokenDeployment,
) -> Result<Response, Error> {
    let token_id = params.xrpl_token.token_id();
    let its_msg = ItsHubMessage::SendToHub {
        destination_chain: params.destination_chain,
        message: ItsMessage::DeployInterchainToken {
            token_id,
            name: params.name,
            symbol: params.symbol,
            decimals: params.decimals,
            minter: params.minter,
        }
    };

    let payload = its_msg.abi_encode();

    let msg = Message {
        cc_id: generate_cross_chain_id(storage, block_height, xrpl_chain_name.clone())?,
        source_address: Address::from_str(&xrpl_multisig_address).unwrap(),
        destination_address: Address::from_str(its_hub.as_str()).unwrap(),
        destination_chain: axelar_chain_name.clone(),
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
    };

    Ok(Response::new().add_messages(router.route(vec![msg.clone()])).add_event(GatewayEvent::RoutingIncoming { msg }.into()))
}

fn generate_cross_chain_id(
    storage: &mut dyn Storage,
    block_height: u64,
    chain_name: ChainName,
) -> Result<CrossChainId, Error> {
    // TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it.
    // Use the block height as the placeholder in the meantime.
    let message_id = HexTxHashAndEventIndex {
        tx_hash: Uint256::from(block_height).to_be_bytes(),
        event_index: state::ROUTABLE_MESSAGES_INDEX
            .incr(storage)
            .change_context(Error::EventIndex)?,
    };

    CrossChainId::new(chain_name, message_id).change_context(Error::InvalidCrossChainId)
}

fn apply(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<XRPLMessage>,
    action: impl Fn(Vec<(VerificationStatus, Vec<XRPLMessage>)>) -> (Option<WasmMsg>, Vec<Event>),
) -> Result<Response, Error> {
    check_for_duplicates(msgs)?
        .then(|msgs| verifier.messages_status(msgs.into_iter().map(|m| m.into()).collect()))
        .change_context(Error::MessageStatus)?
        .then(group_by_status)
        .then(action)
        .then(|(msgs, events)| Response::new().add_messages(msgs).add_events(events))
        .then(Ok)
}

fn check_for_duplicates<T: CrossChainMessage>(msgs: Vec<T>) -> Result<Vec<T>, Error> {
    let duplicates: Vec<_> = msgs
        .iter()
        // the following two map instructions are separated on purpose
        // so the duplicate check is done on the typed id instead of just a string
        .map(|m| m.cc_id())
        .duplicates()
        .map(|cc_id| cc_id.to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(Error::DuplicateMessageIds).attach_printable(duplicates.iter().join(", "));
    }
    Ok(msgs)
}

fn group_by_status(
    msgs_with_status: impl IntoIterator<Item = MessageStatus>,
) -> Vec<(VerificationStatus, Vec<XRPLMessage>)> {
    msgs_with_status
        .into_iter()
        .map(|msg_status| (msg_status.status, msg_status.message))
        .into_group_map()
        .into_iter()
        // sort by verification status so the order of messages is deterministic
        .sorted_by_key(|(status, _)| *status)
        .collect()
}

fn verify(
    verifier: &xrpl_voting_verifier::Client,
    msgs_by_status: Vec<(VerificationStatus, Vec<XRPLMessage>)>,
) -> (Option<WasmMsg>, Vec<Event>) {
    msgs_by_status
        .into_iter()
        .map(|(status, msgs)| {
            (
                filter_verifiable_messages(status, &msgs),
                into_verify_events(status, msgs),
            )
        })
        .then(flat_unzip)
        .then(|(msgs, events)| (verifier.verify_messages(msgs), events))
}

fn route(
    store: &dyn Storage,
    router: &Router,
    msgs_by_status: Vec<(VerificationStatus, Vec<XRPLMessageWithPayload>)>,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig_address: &String,
) -> (Option<WasmMsg>, Vec<Event>) {
    msgs_by_status
        .into_iter()
        .map(|(status, msgs)| {
            let msgs: Vec<Message> = msgs.iter().map(|m| to_its_message(store, m.clone(), its_hub, axelar_chain_name, xrpl_multisig_address)).collect();
            (
                filter_routable_messages(status, &msgs),
                into_route_events(status, msgs),
            )
        })
        .then(flat_unzip)
        .then(|(msgs, events)| (router.route(msgs), events))
}

// not all messages are verifiable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_verifiable_messages(status: VerificationStatus, msgs: &[XRPLMessage]) -> Vec<XRPLMessage> {
    match status {
        VerificationStatus::Unknown
        | VerificationStatus::NotFoundOnSourceChain
        | VerificationStatus::FailedToVerify => msgs.to_vec(),
        _ => vec![],
    }
}

fn into_verify_events(status: VerificationStatus, msgs: Vec<XRPLMessage>) -> Vec<Event> {
    match status {
        VerificationStatus::Unknown
        | VerificationStatus::NotFoundOnSourceChain
        | VerificationStatus::FailedToVerify
        | VerificationStatus::InProgress => {
            messages_into_events(msgs, |msg| GatewayEvent::Verifying { msg })
        }
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::AlreadyVerified { msg })
        }
        VerificationStatus::FailedOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::AlreadyRejected { msg })
        }
    }
}

// not all messages are routable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_routable_messages(status: VerificationStatus, msgs: &[Message]) -> Vec<Message> {
    if status == VerificationStatus::SucceededOnSourceChain {
        msgs.to_vec()
    } else {
        vec![]
    }
}

fn into_route_events(status: VerificationStatus, msgs: Vec<Message>) -> Vec<Event> {
    match status {
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::RoutingIncoming { msg })
        }
        _ => messages_into_events(msgs, |msg| GatewayEvent::UnfitForRouting { msg }),
    }
}

fn flat_unzip<A, B>(x: impl Iterator<Item = (Vec<A>, Vec<B>)>) -> (Vec<A>, Vec<B>) {
    let (x, y): (Vec<_>, Vec<_>) = x.unzip();
    (
        x.into_iter().flatten().collect(),
        y.into_iter().flatten().collect(),
    )
}

fn messages_into_events<T>(msgs: Vec<T>, transform: fn(T) -> GatewayEvent) -> Vec<Event> {
    msgs.into_iter().map(|msg| transform(msg).into()).collect()
}

fn to_its_message(
    store: &dyn Storage,
    msg: XRPLMessageWithPayload,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig_address: &String,
) -> Message {
    match msg.message.clone() {
        XRPLMessage::ProverMessage(_tx_hash) => todo!(),
        XRPLMessage::UserMessage(user_message) => {
            let token_id: TokenId = match user_message.amount.clone() { // TODO: CASE-SENSITIVE?
                XRPLPaymentAmount::Drops(_) => XRPLTokenOrXRP::XRP.token_id(),
                XRPLPaymentAmount::Token(token, _) => state::XRPL_CURRENCY_TO_TOKEN_ID.load(store, token.currency.to_bytes()).unwrap(),
            };

            let interchain_transfer = ItsMessage::InterchainTransfer {
                token_id,
                source_address: HexBinary::from(&user_message.source_address.to_bytes()),
                destination_address: user_message.destination_address,
                amount: user_message.amount.into(),
                data: msg.payload,
            };

            let its_msg = ItsHubMessage::SendToHub {
                destination_chain: user_message.destination_chain,
                message: interchain_transfer,
            };

            let payload = its_msg.abi_encode();

            Message {
                cc_id: msg.message.cc_id(),
                source_address: Address::from_str(xrpl_multisig_address).unwrap(),
                destination_address: Address::from_str(its_hub.as_str()).unwrap(),
                destination_chain: axelar_chain_name.clone(),
                payload_hash: Keccak256::digest(payload.as_slice()).into(),
            }
        },
    }
}