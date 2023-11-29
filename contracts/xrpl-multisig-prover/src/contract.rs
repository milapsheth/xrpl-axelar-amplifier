use std::{str::FromStr, ops::Add, num::NonZeroU32};

#[cfg(not(feature = "library"))]
use axelar_wasm_std::Threshold;
use axelar_wasm_std::{snapshot, Participant};
use cosmwasm_schema::{cw_serde, serde::{de::DeserializeOwned, Serialize}};
use cosmwasm_std::{
    entry_point, Storage, HexBinary, wasm_execute, SubMsg, Reply,
    to_binary, DepsMut, Env, MessageInfo, Response, QueryRequest, WasmQuery, QuerierWrapper,
};
use bs58;
use multisig::key::{KeyType, PublicKey};
use ripemd::Ripemd160;
use sha2::{Sha256, Digest};
use voting_verifier::{state::MessageId, execute::MessageStatus};

use crate::{
    error::ContractError,
    state::{Config, CONFIG, REPLY_TX_HASH, TOKENS, CURRENT_WORKER_SET, WorkerSet, NEXT_WORKER_SET},
    reply,
    types::*,
    xrpl_multisig::{self, XRPLSignerEntry, XRPLPaymentAmount, XRPLUnsignedTx, XRPLSigner, XRPLSignedTransaction, XRPLTokenAmount},
};

use connection_router::state::{Message, CrossChainId, ChainName};
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
    ticket_count_threshold: u32,
}

#[cw_serde]
pub enum ExecuteMsg {
    ConstructProof(CrossChainId, u32),
    UpdateTxStatus(TxHash),
    UpdateWorkerSet(u32),
    TicketCreate(u32),
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
        ticket_count_threshold: msg.ticket_count_threshold,
    };

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

pub fn make_xrpl_signed_tx(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> XRPLSignedTransaction {
    let xrpl_signers: Vec<XRPLSigner> = axelar_signers
        .iter()
        .map(|(axelar_signer, signature)| {
            let xrpl_address = public_key_to_xrpl_address(axelar_signer.pub_key.clone());
            XRPLSigner {
                account: xrpl_address,
                signing_pub_key: axelar_signer.pub_key.clone().into(),
                txn_signature: HexBinary::from(signature.clone().as_ref())
            }
        })
        .collect::<Vec<XRPLSigner>>();

    XRPLSignedTransaction {
        unsigned_tx,
        signers: xrpl_signers,
    }
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

pub fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    tx_hash: TxHash,
) -> Result<Response, ContractError> {
    REPLY_TX_HASH.save(storage, &tx_hash)?;
    let cur_worker_set = CURRENT_WORKER_SET.load(storage)?;
    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        key_id: cur_worker_set.id(),
        msg: tx_hash.into(),
    };

    let wasm_msg = wasm_execute(config.axelar_multisig_address.clone(), &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn construct_payment_proof(
    deps: Deps,
    info: MessageInfo,
    config: &Config,
    message_id: CrossChainId,
    latest_ledger_index: u32,
) -> Result<Response, ContractError> {
    if info.funds.len() != 1 {
        return Err(ContractError::InvalidPaymentAmount);
    }

    let mut funds = info.funds;
    let coin = funds.remove(0);
    let xrpl_token = TOKENS.load(deps.storage, coin.denom.clone())?;
    let message = deps.querier.get_message(message_id.clone())?;
    let drops = u64::try_from(coin.amount.u128() / 10u128.pow(12)).map_err(|_| ContractError::InvalidAmount)?;
    let xrpl_payment_amount = if xrpl_token.currency == XRPLToken::NATIVE_CURRENCY {
        XRPLPaymentAmount::Drops(drops)
    } else {
        XRPLPaymentAmount::Token(
            XRPLToken {
                issuer: xrpl_token.issuer,
                currency: xrpl_token.currency,
            },
            XRPLTokenAmount(drops.to_string()),
        )
    };

    let (tx_hash, _) = xrpl_multisig::issue_payment(
        deps.storage,
        config,
        message.destination_address.to_string().try_into()?,
        xrpl_payment_amount,
        latest_ledger_index,
    )?;

    Ok(
        start_signing_session(
            deps.storage,
            config,
            tx_hash,
        )?
    )
}

fn construct_signer_list_set_proof(
    deps: Deps,
    env: Env,
    config: &Config,
    latest_ledger_index: u32,
) -> Result<Response, ContractError> {
    let workers_info = get_workers_info(deps.querier, config)?;
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

        return Ok(Response::new().add_message(wasm_execute(config.axelar_multisig_address.clone(), &key_gen_msg, vec![])?));
    }

    let signer_list_entries = make_xrpl_signer_entries(workers_info.pubkeys_by_participant.clone());

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

    let (tx_hash, _unsigned_tx) = xrpl_multisig::issue_signer_list_set(
        deps.storage,
        config,
        signer_list_entries,
        latest_ledger_index,
    )?;

    NEXT_WORKER_SET.save(deps.storage, tx_hash.clone(), &(new_worker_set, workers_info.snapshot.quorum))?;

    Ok(
        start_signing_session(
            deps.storage,
            config,
            tx_hash,
        )?
    )
}

fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    config: &Config,
    latest_ledger_index: u32,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::available_ticket_count(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached.into());
    }

    let (tx_hash, _unsigned_tx) = xrpl_multisig::issue_ticket_create(
        storage,
        config,
        ticket_count,
        latest_ledger_index,
    )?;

    let response = start_signing_session(
        storage,
        config,
        tx_hash,
    )?;

    Ok(response)
}

fn update_tx_status(
    deps: Deps,
    tx_hash: TxHash,
) -> Result<Response, ContractError> {
    let confirmations = deps.querier.get_message_confirmation(tx_hash.clone())?;

    let confirmation = confirmations
        .get(0)
        .ok_or(ContractError::TransactionStatusNotConfirmed)?
        .clone()
        .1
        .ok_or(ContractError::TransactionStatusNotConfirmed)?;

    let new_status: TransactionStatus = confirmation.into();

    xrpl_multisig::update_tx_status(deps.storage, tx_hash, new_status)?;
    Ok(Response::default())
}

pub struct Deps<'a> {
    pub storage: &'a mut dyn Storage,
    pub querier: Querier<'a>,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let querier = Querier::new(deps.querier, config.clone());
    let deps = Deps {
        storage: deps.storage,
        querier,
    };

    let res = match msg {
        ExecuteMsg::ConstructProof(message_id, latest_ledger_index) => {
            construct_payment_proof(deps, info, &config, message_id, latest_ledger_index)
        },
        ExecuteMsg::UpdateWorkerSet(latest_ledger_index) => {
            construct_signer_list_set_proof(deps, env, &config, latest_ledger_index)
        },
        ExecuteMsg::UpdateTxStatus(tx_hash) => {
            update_tx_status(deps, tx_hash)
        },
        ExecuteMsg::TicketCreate(latest_ledger_index) => {
            construct_ticket_create_proof(deps.storage, &config, latest_ledger_index)
        },
    }?;

    Ok(res)
}

fn query<U, T>(querier: QuerierWrapper, contract_addr: String, query_msg: &T) -> Result<U, ContractError>
where U: DeserializeOwned, T: Serialize + ?Sized {
    querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr,
        msg: to_binary(&query_msg)?,
    })).map_err(ContractError::from)
}

pub struct Querier<'a> {
    querier: QuerierWrapper<'a>,
    config: Config,
}

impl<'a> Querier<'a> {
    fn new(querier: QuerierWrapper<'a>, config: Config) -> Self {
        Self {
            querier,
            config,
        }
    }

    pub fn get_active_workers(&self) -> Result<Vec<Worker>, ContractError> {
        query(self.querier, self.config.service_registry_address.to_string(),
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: self.config.service_name.clone(),
                chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
            },
        )
    }

    pub fn get_public_key(&self, worker_address: String) -> Result<PublicKey, ContractError> {
        query(self.querier, self.config.axelar_multisig_address.to_string(),
            &multisig::msg::QueryMsg::GetPublicKey {
                worker_address,
                key_type: KeyType::Ecdsa,
            },
        )
    }

    pub fn get_message(&self, message_id: CrossChainId) -> Result<Message, ContractError> {
        let messages: Vec<Message> = query(self.querier, self.config.gateway_address.to_string(),
            &gateway::msg::QueryMsg::GetMessages {
                message_ids: vec![message_id],
            }
        )?;
        Ok(messages[0].clone())
    }

    pub fn get_message_confirmation(&self, tx_hash: TxHash) -> Result<Vec<(MessageId, Option<MessageStatus>)>, ContractError> {
        let confirmations: Vec<(MessageId, Option<MessageStatus>)> = query(self.querier, self.config.voting_verifier_address.to_string(),
            &voting_verifier::msg::QueryMsg::IsConfirmed {
                message_ids: vec![tx_hash.into()],
            }
        )?;
        Ok(confirmations)
    }
}

fn get_workers_info(querier: Querier, config: &Config) -> Result<WorkersInfo, ContractError> {
    let workers: Vec<Worker> = querier.get_active_workers()?;

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
        let pub_key: PublicKey = querier.get_public_key(worker.address.to_string())?;
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
