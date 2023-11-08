#[cfg(not(feature = "library"))]
use axelar_wasm_std::Threshold;
use cosmwasm_schema::{cw_serde, serde::{Serializer, ser::SerializeStruct, Serialize}};
use cosmwasm_std::{
    entry_point, Storage, Uint128, Addr, HexBinary, wasm_execute, SubMsg, Reply,
    to_binary, DepsMut, Env, MessageInfo, Response, QueryRequest, WasmQuery, QuerierWrapper,
};
use sha2::{Digest, Sha512};
use serde_json;

use crate::{
    error::ContractError,
    state::{Config, CONFIG, REPLY_TX_HASH, KEY_ID},
    reply,
};

use connection_router::state::{Message, CrossChainId};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cw_serde]
pub struct InstantiateMsg {
    axelar_multisig_address: String,
    gateway_address: String,
    signing_threshold: Threshold,
    xrpl_multisig_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    ConstructProof(CrossChainId),
}

#[cw_serde]
pub struct QueryMsg {
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let axelar_multisig_address = deps.api.addr_validate(&msg.axelar_multisig_address)?;
    let gateway_address = deps.api.addr_validate(&msg.gateway_address)?;
    let xrpl_multisig_address = deps.api.addr_validate(&msg.xrpl_multisig_address)?;

    let config = Config {
        axelar_multisig_address,
        gateway_address,
        xrpl_multisig_address,
        signing_threshold: msg.signing_threshold,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

pub fn get_message(
    querier: QuerierWrapper,
    message_id: CrossChainId,
    gateway: Addr,
) -> Result<Message, ContractError> {
    let query = gateway::msg::QueryMsg::GetMessages { message_ids: vec![message_id] };
    let mut messages: Vec<Message> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: gateway.into(),
        msg: to_binary(&query)?,
    }))?;

    if messages.len() != 1 {
        // TODO: return error
        // TODO: better error message
        panic!("only one message is allowed");
    }

    let message = messages.remove(0);
    Ok(message)
}

#[cw_serde]
pub enum XRPLTransactionType {
    Payment,
    //TrustSet,
    SignerListSet,
    CreateTicket,
}

fn itoa_serialize<S>(x: &u32, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.to_string()[..])
}

#[cw_serde]
pub struct XRPLTokenAmount {
    currency: String,
    #[serde(serialize_with = "itoa_serialize")]
    value: u32,
    issuer: String,
}

pub enum XRPLPaymentAmount {
    Drops(u32),
    Token(XRPLTokenAmount),
}

impl Serialize for XRPLPaymentAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self {
            XRPLPaymentAmount::Drops(drops) => {
                serializer.serialize_str(&drops.to_string()[..])
            }
            XRPLPaymentAmount::Token(token) => {
                token.serialize(serializer)
            }
        }
    }
}

#[cw_serde]
pub enum Sequence {
    Plain(u32),
    Ticket(u32),
}

const FEE: u32 = 12;

pub struct XRPLUnsignedPaymentTransaction {
    account: String,
    fee: u32,
    sequence: Sequence,
    //LastLedgerSequence: Uint32,
    //Memos: vec<Memo>,
    //Signers: vec<Signer>,
    amount: XRPLPaymentAmount,
    destination: String,
    signing_pub_key: String,
}

impl Serialize for XRPLUnsignedPaymentTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("tx", 3)?;
        state.serialize_field("TransactionType", "Payment")?;
        state.serialize_field("Account", &self.account)?;
        state.serialize_field("Fee", &self.fee.to_string())?;
        match &self.sequence {
            Sequence::Plain(sequence) => {
                state.serialize_field("Sequence", &sequence)?;
            }
            Sequence::Ticket(ticket) => {
                state.serialize_field("Sequence", "0")?;
                state.serialize_field("TicketSequence", &ticket)?;
            }
        }
        state.serialize_field("Amount", &self.amount)?;
        state.serialize_field("Destination", &self.destination)?;
        state.serialize_field("SigningPubKey", &self.signing_pub_key)?;
        state.end()
    }
}

pub const HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

pub fn xrpl_hash(
    prefix: [u8; 4],
    unsigned_tx: &[u8],
) -> [u8; 64] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(unsigned_tx);
    hasher.finalize().into()
}

pub fn construct_proof(
    querier: QuerierWrapper,
    storage: &mut dyn Storage,
    config: Config,
    message_id: CrossChainId,
    amount: Uint128,
    denom: String,
) -> Result<Response, ContractError> {
    let message = get_message(querier, message_id, config.gateway_address)?;
    let drops = u32::try_from(amount.u128() / 10u128.pow(12)).map_err(|_| ContractError::InvalidAmount)?;
    // TODO: compute sequence/ticket number
    let unsigned_tx = XRPLUnsignedPaymentTransaction {
        account: config.xrpl_multisig_address.to_string(),
        fee: FEE,
        sequence: Sequence::Plain(0),
        amount: if denom == "uwasm" { XRPLPaymentAmount::Drops(drops) } else { XRPLPaymentAmount::Token(XRPLTokenAmount {
            issuer: "".to_string(), // TODO: map denom to issuer
            value: drops,
            currency: denom, // TODO: map denom to currency
        }) },
        destination: message.destination_address.to_string(),
        signing_pub_key: "".to_string(),
    };
    // TODO: implement XRPL encoding: https://xrpl.org/serialization.html
    let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx).map_err(|_| ContractError::SerializationFailed)?;

    let tx_hash: HexBinary = HexBinary::from(xrpl_hash(HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI, encoded_unsigned_tx.as_bytes()));
    REPLY_TX_HASH.save(storage, &tx_hash)?;

    let key_id = KEY_ID.load(storage)?;
    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id,
        msg: tx_hash,
    };

    let wasm_msg = wasm_execute(config.axelar_multisig_address, &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    if info.funds.len() != 1 {
        panic!("only one coin is allowed");
    }

    let config = CONFIG.load(deps.storage)?;

    let res = match msg {
        ExecuteMsg::ConstructProof(message_id) => {
            let mut funds = info.funds;
            let coin = funds.remove(0);
            construct_proof(deps.querier, deps.storage, config, message_id, coin.amount, coin.denom)
        },
    }?;

    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_xrpl_unsigned_payment_transaction() {
        let unsigned_tx = XRPLUnsignedPaymentTransaction {
            account: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            fee: FEE,
            sequence: Sequence::Plain(0),
            amount: XRPLPaymentAmount::Token(XRPLTokenAmount {
                currency: "USD".to_string(),
                value: 100,
                issuer: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            }),
            destination: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            signing_pub_key: "".to_string(),
        };
        let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx);
        println!("{}", encoded_unsigned_tx.unwrap());
    }
}
