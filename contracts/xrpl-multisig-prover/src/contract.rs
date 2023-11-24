use std::{str::FromStr, ops::Add, num::NonZeroU32};

#[cfg(not(feature = "library"))]
use axelar_wasm_std::Threshold;
use axelar_wasm_std::{snapshot, Participant};
use cosmwasm_schema::{cw_serde, serde::Serializer};
use cosmwasm_std::{
    entry_point, Storage, Addr, HexBinary, wasm_execute, SubMsg, Reply,
    to_binary, DepsMut, Env, MessageInfo, Response, QueryRequest, WasmQuery, QuerierWrapper,
};
use bs58;
use multisig::key::{KeyType, PublicKey};
use ripemd::Ripemd160;
use sha2::{Sha256, Sha512, Digest};
use serde_json;

use crate::{
    error::ContractError,
    state::{Config, CONFIG, REPLY_TX_HASH, LAST_ASSIGNED_TICKET_NUMBER, AVAILABLE_TICKETS, TRANSACTION_INFO, TOKENS, CURRENT_WORKER_SET, WorkerSet, NEXT_WORKER_SET},
    reply,
    types::*,
};

use connection_router::state::{Message, CrossChainId, ChainName, Address};
use service_registry::state::Worker;

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cw_serde]
pub struct InstantiateMsg {
    axelar_multisig_address: String,
    gateway_address: String,
    signing_quorum: NonZeroU32,
    xrpl_multisig_address: String,
    voting_verifier_address: String,
    service_registry_address: String,
    service_name: String,
    worker_set_diff_threshold: u32,
    xrpl_fee: u64,
    last_ledger_sequence_offset: u32,
}

#[cw_serde]
pub enum ExecuteMsg {
    ConstructProof(CrossChainId, u32),
    UpdateTxStatus(TxHash, bool),
    UpdateWorkerSet(u32),
}

#[cw_serde]
pub struct QueryMsg {
}

const XRPL_CHAIN_NAME: &str = "XRPL";

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
    let voting_verifier_address = deps.api.addr_validate(&msg.voting_verifier_address)?;
    let service_registry_address = deps.api.addr_validate(&msg.service_registry_address)?;

    let config = Config {
        axelar_multisig_address,
        gateway_address,
        xrpl_multisig_address,
        signing_quorum: msg.signing_quorum,
        voting_verifier_address,
        service_registry_address,
        service_name: msg.service_name,
        worker_set_diff_threshold: msg.worker_set_diff_threshold,
        xrpl_fee: msg.xrpl_fee,
        last_ledger_sequence_offset: msg.last_ledger_sequence_offset,
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

impl Into<u32> for Sequence {
    fn into(self) -> u32 {
        match self {
            Sequence::Plain(sequence) => sequence,
            Sequence::Ticket(ticket) => ticket,
        }
    }
}

#[cw_serde]
pub enum XRPLTransactionType {
    Payment,
    //TrustSet,
    SignerListSet,
    CreateTicket,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLTxCommonFields {
    account: String, // TODO: redundant here?
    #[serde(serialize_with = "itoa_serialize")]
    fee: u64,
    sequence: Sequence,
    signing_pub_key: String,
    last_ledger_sequence: u32,
}

#[cw_serde]
#[serde(rename_all = "PascalCase", tag = "SignerEntry")]
pub struct XRPLSignerEntry {
    account: String,
    signer_weight: u16,
}

pub enum XRPLTxType {
    Payment,
    SignerListSet,
    TrustSet,
    CreateTicket,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLUnsignedTx {
    #[serde(flatten)]
    common: XRPLTxCommonFields,
    #[serde(flatten)]
    partial: XRPLPartialTx,
}

#[cw_serde]
#[serde(tag="TransactionType")]
pub enum XRPLPartialTx {
    Payment {
        amount: XRPLPaymentAmount,
        destination: String,
    },
    SignerListSet {
        signer_quorum: NonZeroU32,
        signer_entries: Vec<XRPLSignerEntry>,
    },
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
pub struct XRPLSignedTransaction {
    #[serde(flatten)]
    pub unsigned_tx: XRPLUnsignedTx,
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

impl XRPLSignedTransaction {
    pub fn new(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> Self {
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

impl TryInto<HexBinary> for XRPLSignedTransaction {
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
) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(unsigned_tx);
    let hash: [u8; 64] = hasher.finalize().into();
    let mut half_hash: [u8; 32] = [0; 32];
    half_hash.copy_from_slice(&hash[..32]);
    half_hash
}

pub fn make_xrpl_signer_entries(signers: Vec<(Participant, PublicKey)>) -> Vec<XRPLSignerEntry> {
    // TODO: sum assumed to fit in Uint256
    // TODO: sum assumed to be less than 10^22.5
    let sum_of_weights: cosmwasm_std::Uint256 = signers
        .clone()
        .into_iter()
        .fold(cosmwasm_std::Uint256::zero(), |acc, (participant, _)| {
            let weight: cosmwasm_std::Uint256 = participant.weight.into();
            acc.add(weight)
        });

    signers.into_iter().map(
        |(participant, pub_key)| {
            // TODO: weight assumed to be less than (2^256 - 1) / 10^18
            let weight: cosmwasm_std::Decimal256 = cosmwasm_std::Decimal256::new(participant.weight.into());
            let weight_bytes = (weight * cosmwasm_std::Decimal256::from_ratio(
                cosmwasm_std::Uint256::from(65535u16),
                sum_of_weights)
            ).to_uint_ceil().to_be_bytes();

            XRPLSignerEntry {
                account: public_key_to_xrpl_address(pub_key),
                signer_weight: u16::from_be_bytes(weight_bytes[30..32].try_into().unwrap()),
            }
        }
    ).collect()
}

pub fn should_update_worker_set(
    new_workers: &WorkerSet,
    cur_workers: &WorkerSet,
    max_diff: usize,
) -> bool {
    new_workers.signers.difference(&cur_workers.signers).count()
        + cur_workers.signers.difference(&new_workers.signers).count()
        > max_diff
}

fn get_next_ticket_number(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    // find next largest in available, otherwise use available_tickets[0]
    let ticket_number = available_tickets.iter().find(|&x| x > &last_assigned_ticket_number).unwrap_or(&available_tickets[0]);
    Ok(*ticket_number)
}

pub fn construct_proof(
    storage: &mut dyn Storage,
    config: Config,
    partial_tx: XRPLPartialTx,
    latest_ledger_index: u32,
) -> Result<(Response, TxHash), ContractError> {
    let ticket_number = get_next_ticket_number(storage)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(storage, &(ticket_number + 1))?;

    let unsigned_tx_common = XRPLTxCommonFields {
        account: config.xrpl_multisig_address.to_string(),
        fee: config.xrpl_fee,
        sequence: Sequence::Ticket(ticket_number.clone()),
        signing_pub_key: "".to_string(),
        last_ledger_sequence: latest_ledger_index + config.last_ledger_sequence_offset,
    };

    let unsigned_tx = XRPLUnsignedTx {
        common: unsigned_tx_common,
        partial: partial_tx,
    };

    // TODO: implement XRPL encoding: https://xrpl.org/serialization.html
    let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx).map_err(|_| ContractError::SerializationFailed)?;

    let tx_hash_hex: HexBinary = HexBinary::from(xrpl_hash(HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI, encoded_unsigned_tx.as_bytes()));
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    REPLY_TX_HASH.save(storage, &tx_hash)?;
    TRANSACTION_INFO.save(
        storage,
        tx_hash.clone(),
        &TransactionInfo {
            status: TransactionStatus::Pending,
            unsigned_contents: unsigned_tx,
        }
    )?;

    let cur_worker_set = CURRENT_WORKER_SET.load(storage)?;
    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id: cur_worker_set.id(),
        msg: tx_hash_hex,
    };

    let wasm_msg = wasm_execute(config.axelar_multisig_address, &start_sig_msg, vec![])?;

    Ok((
        Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)),
        tx_hash,
    ))
}

pub enum XRPLMessage {
    Payment(Address, u64, XRPLToken),
    SignerListSet(WorkersInfo),
    CreateTicket(), // TODO
    TrustSet(), // TODO: https://xrpl.org/trustset.html
}

fn construct_payment_proof(
    deps: DepsMut,
    info: MessageInfo,
    config: Config,
    message_id: CrossChainId,
    latest_ledger_index: u32,
) -> Result<Response, ContractError> {
    if info.funds.len() != 1 {
        panic!("only one coin is allowed");
    }

    let mut funds = info.funds;
    let coin = funds.remove(0);
    let xrpl_token = TOKENS.load(deps.storage, coin.denom.clone())?;
    let message = get_message(deps.querier, message_id.clone(), config.gateway_address.clone())?;
    let drops = u64::try_from(coin.amount.u128() / 10u128.pow(12)).map_err(|_| ContractError::InvalidAmount)?;
    let partial_unsigned_tx = XRPLPartialTx::Payment {
        amount: if xrpl_token.currency == XRPLToken::NATIVE_CURRENCY {
            XRPLPaymentAmount::Drops(drops)
        } else {
            XRPLPaymentAmount::Token(
                XRPLToken {
                    issuer: xrpl_token.issuer,
                    currency: xrpl_token.currency,
                },
                XRPLTokenAmount(drops.to_string()),
            )
        },
        destination: message.destination_address.to_string(),
    };

    Ok(
        construct_proof(
            deps.storage,
            config,
            partial_unsigned_tx,
            latest_ledger_index,
        )?.0
    )
}

fn construct_signer_list_set_proof(
    deps: DepsMut,
    env: Env,
    config: Config,
    latest_ledger_index: u32,
) -> Result<Response, ContractError> {
    let workers_info = get_workers_info(deps.querier, &config)?;
    if !CURRENT_WORKER_SET.exists(deps.storage) {
        let new_worker_set = WorkerSet::new(
            workers_info.pubkeys_by_participant.clone(),
            workers_info.snapshot.quorum.into(),
            env.block.height,
        );

        CURRENT_WORKER_SET.save(deps.storage, &new_worker_set)?;
        let key_gen_msg =  multisig::msg::ExecuteMsg::KeyGen {
            key_id: new_worker_set.id(),
            snapshot: workers_info.snapshot,
            pub_keys_by_address: workers_info
                .pubkeys_by_participant
                .clone()
                .into_iter()
                .map(|(participant, pub_key)| {
                    (
                        participant.address.to_string(),
                        (KeyType::Ecdsa, pub_key.as_ref().into()),
                    )
                })
                .collect(),
        };

        return Ok(Response::new().add_message(wasm_execute(config.axelar_multisig_address, &key_gen_msg, vec![])?));
    }

    let partial_unsigned_tx = XRPLPartialTx::SignerListSet {
        signer_quorum: config.signing_quorum,
        signer_entries: make_xrpl_signer_entries(workers_info.pubkeys_by_participant.clone()),
    };

    let new_worker_set = WorkerSet::new(
        workers_info.pubkeys_by_participant,
        workers_info.snapshot.quorum.into(),
        env.block.height,
    );

    let cur_worker_set = CURRENT_WORKER_SET.load(deps.storage)?;
    if should_update_worker_set(
        &new_worker_set,
        &cur_worker_set,
        config.worker_set_diff_threshold as usize,
    ) {
        return Err(ContractError::WorkerSetUnchanged.into())
    }

    let (response, tx_hash) = construct_proof(deps.storage, config, partial_unsigned_tx, latest_ledger_index)?;
    NEXT_WORKER_SET.save(deps.storage, tx_hash, &(new_worker_set, workers_info.snapshot.quorum))?;
    Ok(response)
}

fn update_tx_status(
    storage: &mut dyn Storage,
    sender: Addr,
    voting_verifier_address: Addr,
    tx_hash: TxHash,
    status: bool,
) -> Result<Response, ContractError> {
    // TODO: allow any sender to call, but query the voting verifier
    // to get the status
    if sender != voting_verifier_address {
        return Err(ContractError::Unauthorized);
    }

    let mut tx_info = TRANSACTION_INFO.load(storage, tx_hash.clone())?;
    tx_info.status = if status { TransactionStatus::Succeeded } else { TransactionStatus::Failed };
    TRANSACTION_INFO.save(storage, tx_hash, &tx_info)?;
    AVAILABLE_TICKETS.update(storage, |tickets| -> Result<_, ContractError> {
        let new_available_tickets: Vec<u32> = tickets
            .iter()
            .filter(|&x| {
                let sequence_number: u32 = tx_info.unsigned_contents.common.sequence.clone().into();
                *x != sequence_number
            })
            .cloned()
            .collect();
        Ok(new_available_tickets)
    })?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let res = match msg {
        ExecuteMsg::ConstructProof(message_id, latest_ledger_index) => {
            construct_payment_proof(deps, info, config, message_id, latest_ledger_index)
        },
        ExecuteMsg::UpdateWorkerSet(latest_ledger_index) => {
            construct_signer_list_set_proof(deps, env, config, latest_ledger_index)
        },
        ExecuteMsg::UpdateTxStatus(tx_hash, status) => {
            update_tx_status(
                deps.storage,
                info.sender,
                config.voting_verifier_address,
                tx_hash,
                status
            )
        },
    }?;

    Ok(res)
}

fn get_workers_info(querier: QuerierWrapper, config: &Config) -> Result<WorkersInfo, ContractError> {
    let active_workers_query = service_registry::msg::QueryMsg::GetActiveWorkers {
        service_name: config.service_name.clone(),
        chain_name: ChainName::from_str(XRPL_CHAIN_NAME)
            .map_err(|_| ContractError::InvalidChainName)?,
    };

    let workers: Vec<Worker> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.service_registry_address.to_string(),
        msg: to_binary(&active_workers_query)?,
    }))?;

    let participants = workers
        .clone()
        .into_iter()
        .map(service_registry::state::Worker::try_into)
        .collect::<Result<Vec<snapshot::Participant>, _>>()?;

    let signing_threshold = Threshold::try_from((config.signing_quorum.get() as u64, std::u32::MAX as u64)).unwrap();
    let snapshot =
        snapshot::Snapshot::new(signing_threshold, participants.clone().try_into()?);

    let mut pub_keys = vec![];
    for worker in &workers {
        let pub_key_query = multisig::msg::QueryMsg::GetPublicKey {
            worker_address: worker.address.to_string(),
            key_type: KeyType::Ecdsa, // TODO: why just Ecdsa?
        };
        let pub_key: PublicKey = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.axelar_multisig_address.to_string(),
            msg: to_binary(&pub_key_query)?,
        }))?;
        pub_keys.push(pub_key);
    }

    Ok(WorkersInfo {
        snapshot,
        pubkeys_by_participant: participants.into_iter().zip(pub_keys).collect(),
    })
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

    /*#[test]
    fn serialize_xrpl_unsigned_token_payment_transaction() {
        let unsigned_tx = XRPLUnsignedPaymentTransaction {
            common: XRPLTxCommonFields {
                account: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
                fee: FEE,
                sequence: Sequence::Plain(0),
            },
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
    fn serialize_xrpl_signer_list_set_transaction() {
        let unsigned_tx = XRPLUnsignedPaymentTransaction {
            common: XRPLTxCommonFields {
                account: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
                fee: FEE,
                sequence: Sequence::Plain(0),
            },
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
            common: XRPLTxCommonFields {
                account: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
                fee: FEE,
                sequence: Sequence::Plain(0),
            },
            amount: XRPLPaymentAmount::Drops(10),
            destination: "axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs".to_string(),
            signing_pub_key: "".to_string(),
        };
        let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx);
        println!("{}", encoded_unsigned_tx.unwrap());
    }*/

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
