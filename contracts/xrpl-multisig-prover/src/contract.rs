#[cfg(not(feature = "library"))]
use axelar_wasm_std::Threshold;
use cosmwasm_schema::{cw_serde, serde::Serializer};
use cosmwasm_std::{
    entry_point, Storage, Uint128, Addr, HexBinary, wasm_execute, SubMsg, Reply,
    to_binary, DepsMut, Env, MessageInfo, Response, QueryRequest, WasmQuery, QuerierWrapper,
};
use bs58;
use ripemd::Ripemd160;
use sha2::{Sha256, Sha512, Digest};
use serde_json;

use crate::{
    error::ContractError,
    state::{Config, CONFIG, REPLY_TX_HASH, KEY_ID, LAST_ASSIGNED_TICKET_NUMBER, AVAILABLE_TICKETS, TRANSACTION_INFO, TOKENS},
    reply,
    types::*,
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

fn itoa_serialize<S>(x: &u64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.to_string()[..])
}

#[cw_serde]
pub struct XRPLTokenAmount(String);

#[cw_serde]
#[serde(untagged)]
pub enum XRPLPaymentAmount {
    Drops(
        #[serde(serialize_with = "itoa_serialize")]
        u64,
    ),
    Token(XRPLToken, XRPLTokenAmount),
}

/*impl Serialize for XRPLPaymentAmount {
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
}*/

#[cw_serde]
#[serde(untagged)]
pub enum Sequence {
    Plain(u32),
    Ticket(u32),
}

const FEE: u64 = 12;

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLUnsignedPaymentTransaction {
    account: String,
    #[serde(serialize_with = "itoa_serialize")]
    fee: u64,
    sequence: Sequence,
    //LastLedgerSequence: Uint32,
    //Memos: vec<Memo>,
    //Signers: vec<Signer>,
    amount: XRPLPaymentAmount,
    destination: String,
    signing_pub_key: String,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct Signer {
    pub account: String,
    pub txn_signature: HexBinary,
    pub signing_pub_key: HexBinary,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLSignedPaymentTransaction {
    #[serde(flatten)]
    pub unsigned_tx: XRPLUnsignedPaymentTransaction,
    pub signers: Vec<Signer>,
}

pub fn public_key_to_xrpl_address(public_key: multisig::key::PublicKey) -> String {
    let public_key_hex: HexBinary = public_key.into();

    assert!(public_key_hex.len() == 33);

    let public_key_inner_hash = Sha256::digest(public_key_hex);
    let account_id = Ripemd160::digest(public_key_inner_hash);

    let address_type_prefix: &[u8] = &[0x00];
    let payload = [address_type_prefix, &account_id].concat();

    let checksum_hash1 = Sha256::digest(payload.clone());
    let checksum_hash2 = Sha256::digest(checksum_hash1);
    let checksum = &checksum_hash2[0..4];

    bs58::encode([payload, checksum.to_vec()].concat())
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

impl XRPLSignedPaymentTransaction {
    pub fn new(unsigned_tx: XRPLUnsignedPaymentTransaction, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> Self {
        let xrpl_signers: Vec<Signer> = axelar_signers
            .iter()
            .map(|(axelar_signer, signature)| {
                let xrpl_address = public_key_to_xrpl_address(axelar_signer.pub_key.clone());
                Signer {
                    account: xrpl_address,
                    signing_pub_key: axelar_signer.pub_key.clone().into(),
                    txn_signature: HexBinary::from(signature.clone().as_ref())
                }
            })
            .collect::<Vec<Signer>>();

        Self {
            unsigned_tx,
            signers: xrpl_signers,
        }
    }
}

impl TryInto<HexBinary> for XRPLSignedPaymentTransaction {
    type Error = ContractError;
    fn try_into(self) -> Result<HexBinary, ContractError> {
        Ok(HexBinary::from(serde_json::to_string(&self)
            .map_err(|_| ContractError::SerializationFailed)?
            .as_bytes()))
    }
}

/*impl Serialize for XRPLUnsignedPaymentTransaction {
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
}*/

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
    token: XRPLToken,
) -> Result<Response, ContractError> {
    let last_assigned_ticket_number = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    // find next largest in available, otherwise use available_tickets[0]
    let ticket_number = available_tickets.iter().find(|&x| x > &last_assigned_ticket_number).unwrap_or(&available_tickets[0]);

    LAST_ASSIGNED_TICKET_NUMBER.save(storage, &(ticket_number + 1))?;

    let message = get_message(querier, message_id.clone(), config.gateway_address)?;
    let drops = u64::try_from(amount.u128() / 10u128.pow(12)).map_err(|_| ContractError::InvalidAmount)?;
    let unsigned_tx = XRPLUnsignedPaymentTransaction {
        account: config.xrpl_multisig_address.to_string(),
        fee: FEE,
        sequence: Sequence::Ticket(ticket_number.clone()), // TODO: add CreateTicket logic
        amount: if token.currency == XRPLToken::NATIVE_CURRENCY {
            XRPLPaymentAmount::Drops(drops)
        } else {
            XRPLPaymentAmount::Token(
                XRPLToken {
                    issuer: token.issuer,
                    currency: token.currency,
                },
                XRPLTokenAmount(drops.to_string()),
            )
        },
        destination: message.destination_address.to_string(),
        signing_pub_key: "".to_string(),
    };
    // TODO: implement XRPL encoding: https://xrpl.org/serialization.html
    let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx).map_err(|_| ContractError::SerializationFailed)?;

    let tx_hash_hex: HexBinary = HexBinary::from(xrpl_hash(HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI, encoded_unsigned_tx.as_bytes()));
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    REPLY_TX_HASH.save(storage, &tx_hash)?;
    TRANSACTION_INFO.save(
        storage,
        tx_hash,
        &TransactionInfo {
            sequence_number: ticket_number.clone(),
            status: TransactionStatus::Pending,
            unsigned_contents: unsigned_tx,
            message_id,
        }
    )?;

    let key_id = KEY_ID.load(storage)?;
    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id,
        msg: tx_hash_hex,
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
    let config = CONFIG.load(deps.storage)?;

    // mapping AxelarToken -> XRPLToken
    // mapping (axelar_denom => (xrpl_issuer, xrpl_currency))

    let res = match msg {
        ExecuteMsg::ConstructProof(message_id) => {
            if info.funds.len() != 1 {
                panic!("only one coin is allowed");
            }
            let mut funds = info.funds;
            let coin = funds.remove(0);
            let xrpl_token = TOKENS.load(deps.storage, coin.denom.clone())?;
            construct_proof(deps.querier, deps.storage, config, message_id, coin.amount, xrpl_token)
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
    use multisig::key::PublicKey;

    use super::*;

    #[test]
    fn serialize_xrpl_unsigned_token_payment_transaction() {
        let unsigned_tx = XRPLUnsignedPaymentTransaction {
            account: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            fee: FEE,
            sequence: Sequence::Plain(0),
            amount: XRPLPaymentAmount::Token(
                XRPLToken {
                    currency: "USD".to_string(),
                    issuer: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
                },
                XRPLTokenAmount("100".to_string()),
            ),
            destination: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            signing_pub_key: "".to_string(),
        };
        let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx);
        println!("{}", encoded_unsigned_tx.unwrap());
    }

    #[test]
    fn serialize_xrpl_unsigned_xrp_payment_transaction() {
        let unsigned_tx = XRPLUnsignedPaymentTransaction {
            account: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            fee: FEE,
            sequence: Sequence::Plain(0),
            amount: XRPLPaymentAmount::Drops(10),
            destination: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            signing_pub_key: "".to_string(),
        };
        let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx);
        println!("{}", encoded_unsigned_tx.unwrap());
    }

    #[test]
    fn ed25519_public_key_to_xrpl_address() {
        assert_eq!(
            public_key_to_xrpl_address(PublicKey::Ed25519(HexBinary::from(hex::decode("ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32").unwrap()))),
            "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
        );
    }

    #[test]
    fn secp256k1_public_key_to_xrpl_address() {
        assert_eq!(
            public_key_to_xrpl_address(PublicKey::Ecdsa(HexBinary::from(hex::decode("0303E20EC6B4A39A629815AE02C0A1393B9225E3B890CAE45B59F42FA29BE9668D").unwrap()))),
            "rnBFvgZphmN39GWzUJeUitaP22Fr9be75H"
        );
    }
}
