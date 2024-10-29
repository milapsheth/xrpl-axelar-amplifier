use std::str::FromStr;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, HexBinary};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId, Message, FIELD_DELIMITER};
use sha3::{Keccak256, Digest};
use crate::types::{XRPLPaymentAmount, XRPLAccountId};

pub const CHAIN_NAME: &str = "xrpl"; // TODO

pub struct MemoDetails {
    pub destination_chain: ChainName,
    pub destination_address: Address,
    pub payload_hash: [u8; 32],
}

pub type XRPLHash = [u8; 32];

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLMessageWithPayload {
    pub message: XRPLMessage, // TODO: Should be XRPLUserMessage
    pub payload: Option<nonempty::HexBinary>,
}

impl From<XRPLMessageWithPayload> for XRPLMessage {
    fn from(other: XRPLMessageWithPayload) -> Self {
        other.message
    }
}

impl CrossChainMessage for XRPLMessageWithPayload {
    fn cc_id(&self) -> CrossChainId {
        self.message.cc_id()
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLMessage {
    ProverMessage(XRPLHash),
    UserMessage(UserMessage),
}

impl XRPLMessage {
    pub fn tx_id(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(tx_id) => *tx_id,
            XRPLMessage::UserMessage(user_message) => user_message.tx_id,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(tx_id) => *tx_id,
            XRPLMessage::UserMessage(user_message) => user_message.hash(),
        }
    }
}

pub mod xrpl_account_id_hex {
    use super::XRPLAccountId;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &XRPLAccountId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        axelar_wasm_std::hex::serialize(value.as_ref(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<XRPLAccountId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 20] = axelar_wasm_std::hex::deserialize(deserializer)?;
        Ok(XRPLAccountId::from(bytes))
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct UserMessage {
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub tx_id: XRPLHash, // TODO: use TxHash from xrpl_multisig_prover
    #[serde(with = "xrpl_account_id_hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub source_address: XRPLAccountId,
    pub destination_chain: ChainName,
    pub destination_address: nonempty::HexBinary,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
    pub amount: XRPLPaymentAmount,
}

impl From<UserMessage> for Vec<Attribute> {
    fn from(other: UserMessage) -> Self {
        vec![
            ("tx_id", HexBinary::from(other.tx_id).to_string()).into(),
            ("source_address", other.source_address.to_string()).into(),
            ("destination_chain", other.destination_chain).into(),
            ("destination_address", other.destination_address.to_string()).into(),
            (
                "payload_hash",
                HexBinary::from(other.payload_hash).to_string(),
            )
                .into(),
            // TODO: token, amount
            ("amount", other.amount.to_string()).into(),
        ]
    }
}

impl From<XRPLMessage> for Vec<Attribute> {
    fn from(other: XRPLMessage) -> Self {
        match other {
            XRPLMessage::ProverMessage(tx_id) => {
                vec![
                    ("tx_id", HexBinary::from(tx_id).to_string()).into(),
                    ("type", "prover_message").into(),
                ]
            },
            XRPLMessage::UserMessage(msg) => {
                let mut res: Vec<Attribute> = msg.into();
                res.push(
                    ("type", "user_message").into()
                );
                res
            },
        }
    }
}

impl UserMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8]; // TODO: check if this works for XRPL too

        hasher.update(self.tx_id);
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.to_bytes());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.payload_hash);

        hasher.finalize().into()
    }
}

pub trait CrossChainMessage {
    fn cc_id(&self) -> CrossChainId;
}

impl CrossChainMessage for Message {
    fn cc_id(&self) -> CrossChainId {
        self.cc_id.clone()
    }
}

impl CrossChainMessage for XRPLMessage {
    fn cc_id(&self) -> CrossChainId {
        CrossChainId {
            source_chain: ChainNameRaw::from_str(CHAIN_NAME).unwrap(),
            message_id: format!("0x{}", HexBinary::from(self.tx_id()).to_hex()).try_into().unwrap(),
        }
    }
}