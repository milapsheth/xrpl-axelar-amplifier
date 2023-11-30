use std::collections::BTreeSet;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, serde::Serializer};
use cosmwasm_std::{Storage, HexBinary};
use ripemd::Ripemd160;
use sha2::{Sha512, Digest, Sha256};
use serde_json;

use crate::{
    error::ContractError,
    state::{Config, LAST_ASSIGNED_TICKET_NUMBER, AVAILABLE_TICKETS, TRANSACTION_INFO, LATEST_TICKET_CREATE_TX_HASH, NEXT_SEQUENCE_NUMBER},
    types::*, axelar_workers::{WorkerSet, AxelarSigner},
};

/*
    // Administer tickets, sequence numbers, unsigned tx generation
    XRPLMultisig(storage, address, sequence_number, PastTransactions: (Map<TxHash, TxInfo>,Map<SeqNumber, TxHash>)
    IssueTicketCreate(ticket_count | max, last_ledger_index) -> UnsignedTx
    IssuePayment(destination, amount, currency, last_ledger_index) -> UnsignedTx
    IssueSignerListSet(new_worker_set, last_ledger_index) -> UnsignedTx
    IssueTrustLine(account, amount, last_ledger_index) -> UnsignedTx
    UpdateTxStatus(TxHash, Status) -> ()
    // GetTxStatus(TxHash) -> TxStatus
    // IsPendingTicketCreate() -> bool
*/

fn itoa_serialize<S>(x: &u64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.to_string()[..])
}

#[cw_serde]
pub struct XRPLTokenAmount(pub String);

#[cw_serde]
#[serde(untagged)]
pub enum XRPLPaymentAmount {
    Drops(
        #[serde(serialize_with = "itoa_serialize")]
        u64,
    ),
    Token(XRPLToken, XRPLTokenAmount),
}

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
#[serde(rename_all = "PascalCase")]
pub struct XRPLTxCommonFields {
    pub account: String, // TODO: redundant here?
    #[serde(serialize_with = "itoa_serialize")]
    pub fee: u64,
    pub sequence: Sequence,
    pub signing_pub_key: String,
    pub last_ledger_sequence: u32,
}

#[cw_serde]
#[serde(rename_all = "PascalCase", tag = "SignerEntry")]
pub struct XRPLSignerEntry {
    pub account: String,
    pub signer_weight: u16,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLUnsignedTx {
    #[serde(flatten)]
    pub common: XRPLTxCommonFields,
    #[serde(flatten)]
    pub partial: XRPLPartialTx,
}

#[cw_serde]
#[serde(tag="TransactionType")]
pub enum XRPLPartialTx {
    Payment {
        amount: XRPLPaymentAmount,
        destination: nonempty::String,
    },
    SignerListSet {
        signer_quorum: u32,
        signer_entries: Vec<XRPLSignerEntry>,
    },
    TicketCreate {
        ticket_count: u32,
    },
}

impl XRPLUnsignedTx {
    pub fn sequence_number_increment(&self, status: TransactionStatus) -> u32 {
        if status == TransactionStatus::Pending || status == TransactionStatus::FailedOffChain {
            return 0;
        }

        match self.partial {
            XRPLPartialTx::Payment { .. } |
            XRPLPartialTx::SignerListSet { .. } => {
                match self.common.sequence {
                    Sequence::Plain(_) => 1,
                    Sequence::Ticket(_) => 0,
                }
            },
            XRPLPartialTx::TicketCreate { ticket_count } => {
                match status {
                    TransactionStatus::Succeeded => ticket_count + 1,
                    TransactionStatus::FailedOnChain => 1,
                    TransactionStatus::FailedOffChain |
                    TransactionStatus::Pending => unreachable!(),
                }
            },
        }
    }
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLSigner {
    pub account: String,
    pub txn_signature: HexBinary,
    pub signing_pub_key: HexBinary,
}

#[cw_serde]
#[serde(rename_all = "PascalCase")]
pub struct XRPLSignedTransaction {
    #[serde(flatten)]
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>,
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

fn get_next_ticket_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    // find next largest in available, otherwise use available_tickets[0]
    let ticket_number = available_tickets.iter().find(|&x| x > &last_assigned_ticket_number).unwrap_or(&available_tickets[0]);
    Ok(*ticket_number)
}

pub fn available_ticket_count(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let ticket_count = 250 - (available_tickets.len() as u32);
    Ok(ticket_count)
}

fn construct_unsigned_tx(
    config: &Config,
    partial_unsigned_tx: XRPLPartialTx,
    latest_ledger_index: u32,
    sequence: Sequence,
) -> XRPLUnsignedTx {
    let unsigned_tx_common = XRPLTxCommonFields {
        account: config.xrpl_multisig_address.to_string(),
        fee: config.xrpl_fee,
        sequence: sequence.clone(),
        signing_pub_key: "".to_string(),
        last_ledger_sequence: latest_ledger_index + config.last_ledger_sequence_offset,
    };

    XRPLUnsignedTx {
        common: unsigned_tx_common,
        partial: partial_unsigned_tx,
    }
}

fn compute_tx_hash(unsigned_tx: XRPLUnsignedTx) -> Result<TxHash, ContractError> {
    // TODO: implement XRPL encoding: https://xrpl.org/serialization.html
    let encoded_unsigned_tx = serde_json::to_string(&unsigned_tx).map_err(|_| ContractError::SerializationFailed)?;

    let tx_hash_hex: HexBinary = HexBinary::from(xrpl_hash(HASH_PREFIX_UNSIGNED_TRANSACTION_MULTI, encoded_unsigned_tx.as_bytes()));
    let tx_hash: TxHash = TxHash(tx_hash_hex.clone());
    Ok(tx_hash)
}

fn issue_tx(
    storage: &mut dyn Storage,
    config: &Config,
    partial_unsigned_tx: XRPLPartialTx,
    latest_ledger_index: u32,
    sequence: Sequence,
) -> Result<TxHash, ContractError> {
    let unsigned_tx = construct_unsigned_tx(
        config,
        partial_unsigned_tx,
        latest_ledger_index,
        sequence.clone(),
    );

    let tx_hash = compute_tx_hash(unsigned_tx.clone())?;

    TRANSACTION_INFO.save(
        storage,
        tx_hash.clone(),
        &TransactionInfo {
            status: TransactionStatus::Pending,
            unsigned_contents: unsigned_tx.clone(),
        }
    )?;

    if let Sequence::Ticket(ticket_number) = sequence {
        LAST_ASSIGNED_TICKET_NUMBER.save(storage, &ticket_number)?;
    }

    Ok(tx_hash)
}

pub fn issue_ticket_create(storage: &mut dyn Storage, config: &Config, ticket_count: u32, latest_ledger_index: u32) -> Result<TxHash, ContractError> {
    let partial_unsigned_tx = XRPLPartialTx::TicketCreate {
        ticket_count,
    };

    let latest_ticket_create_tx_info = load_latest_ticket_create_tx_info(storage)?;
    let sequence_number = if latest_ticket_create_tx_info.status == TransactionStatus::Pending {
        latest_ticket_create_tx_info.unsigned_contents.common.sequence.clone().into()
    } else {
        NEXT_SEQUENCE_NUMBER.load(storage)?
    };

    let tx_hash = issue_tx(
        storage,
        config,
        partial_unsigned_tx,
        latest_ledger_index,
        Sequence::Plain(sequence_number)
    )?;

    LATEST_TICKET_CREATE_TX_HASH.save(storage, &tx_hash)?;
    Ok(tx_hash)
}

fn load_latest_ticket_create_tx_info(
    storage: &dyn Storage,
) -> Result<TransactionInfo, ContractError> {
    let latest_ticket_create_tx_hash = LATEST_TICKET_CREATE_TX_HASH.load(storage)?;
    Ok(TRANSACTION_INFO.load(storage, latest_ticket_create_tx_hash.clone())?)
}

pub fn issue_payment(storage: &mut dyn Storage, config: &Config, destination: nonempty::String, amount: XRPLPaymentAmount, latest_ledger_index: u32) -> Result<TxHash, ContractError> {
    let partial_unsigned_tx = XRPLPartialTx::Payment {
        destination,
        amount,
    };

    let ticket_number = get_next_ticket_number(storage)?;
    issue_tx(
        storage,
        config,
        partial_unsigned_tx,
        latest_ledger_index,
        Sequence::Ticket(ticket_number)
    )
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

pub fn make_xrpl_signer_entries(signers: BTreeSet<AxelarSigner>) -> Vec<XRPLSignerEntry> {
    signers
        .into_iter()
        .map(
            |worker| {
                XRPLSignerEntry {
                    account: public_key_to_xrpl_address(worker.pub_key),
                    signer_weight: worker.weight,
                }
            }
        ).collect()
}

pub fn issue_signer_list_set(storage: &mut dyn Storage, config: &Config, workers: WorkerSet, latest_ledger_index: u32) -> Result<TxHash, ContractError> {
    let partial_unsigned_tx = XRPLPartialTx::SignerListSet {
        signer_quorum: workers.quorum,
        signer_entries: make_xrpl_signer_entries(workers.signers),
    };

    let ticket_number = get_next_ticket_number(storage)?;
    issue_tx(
        storage,
        config,
        partial_unsigned_tx,
        latest_ledger_index,
        Sequence::Ticket(ticket_number)
    )
}

fn mark_tickets_available(storage: &mut dyn Storage, tickets: impl Iterator<Item = u32>) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |available_tickets| -> Result<_, ContractError> {
        let mut new_available_tickets = available_tickets.clone();
        for i in tickets {
            new_available_tickets.push(i);
        }

        Ok(new_available_tickets)
    })?;
    Ok(())
}

fn mark_ticket_unavailable(storage: &mut dyn Storage, ticket: u32) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |available_tickets| -> Result<_, ContractError> {
        Ok(available_tickets
            .into_iter()
            .filter(|&x| x != ticket)
            .collect())
    })?;
    Ok(())
}

pub fn update_tx_status(storage: &mut dyn Storage, tx_hash: TxHash, new_status: TransactionStatus) -> Result<(), ContractError> {
    let mut tx_info = TRANSACTION_INFO.load(storage, tx_hash.clone())?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusAlreadyUpdated);
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number: u32 = tx_info.unsigned_contents.common.sequence.clone().into();
    if let XRPLPartialTx::TicketCreate { ticket_count } = tx_info.unsigned_contents.partial {
        if tx_info.status == TransactionStatus::Succeeded {
            mark_tickets_available(
                storage,
                (tx_sequence_number + 1)..(tx_sequence_number + ticket_count),
            )?;
        }
    }

    let sequence_number_increment = tx_info.unsigned_contents.sequence_number_increment(new_status.clone());
    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(storage, &(tx_sequence_number + sequence_number_increment))?;
    }

    if new_status != TransactionStatus::FailedOffChain {
        if let Sequence::Ticket(ticket_number) = tx_info.unsigned_contents.common.sequence {
            mark_ticket_unavailable(storage, ticket_number)?;
        }
    }

    TRANSACTION_INFO.save(storage, tx_hash, &tx_info)?;
    Ok(())
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
