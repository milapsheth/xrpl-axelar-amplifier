use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Attribute, HexBinary};
use router_api::{ChainName, ChainNameRaw, CrossChainId, Message, FIELD_DELIMITER};
use sha3::{Keccak256, Digest};
use crate::types::{TxHash, XRPLAccountId, XRPLPaymentAmount, xrpl_account_id_string, tx_hash_hex};
use crate::hex_option;

#[cw_serde]
#[derive(Eq, Hash)]
pub enum XRPLMessage {
    ProverMessage(
        #[serde(with = "tx_hash_hex")]
        #[schemars(with = "String")]
        TxHash
    ),
    UserMessage(XRPLUserMessage),
}

impl XRPLMessage {
    pub fn tx_id(&self) -> TxHash {
        match self {
            XRPLMessage::ProverMessage(tx_id) => tx_id.clone(),
            XRPLMessage::UserMessage(user_message) => user_message.tx_id.clone(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        match self {
            XRPLMessage::ProverMessage(tx_id) => tx_id.clone().into(),
            XRPLMessage::UserMessage(user_message) => user_message.hash(),
        }
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct XRPLUserMessage {
    #[serde(with = "tx_hash_hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub tx_id: TxHash,
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")]
    pub source_address: XRPLAccountId,
    pub destination_chain: ChainName,
    pub destination_address: nonempty::HexBinary,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "hex_option")]
    #[schemars(with = "String")]
    pub payload_hash: Option<[u8; 32]>,
    pub amount: XRPLPaymentAmount,
}

impl From<XRPLUserMessage> for Vec<Attribute> {
    fn from(other: XRPLUserMessage) -> Self {
        let mut array = vec![
            ("tx_id", HexBinary::from(other.tx_id).to_string()).into(),
            ("source_address", other.source_address.to_string()).into(),
            ("destination_chain", other.destination_chain).into(),
            ("destination_address", other.destination_address.to_string()).into(),
            ("amount", other.amount.to_string()).into(),
        ];

        array.extend(
            match other.payload_hash {
                Some(hash) => vec![
                    ("payload_hash", HexBinary::from(hash).to_string()).into(),
                ],
                None => vec![],
            }
        );

        array
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

impl XRPLUserMessage {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.tx_id.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.amount.hash());

        match self.payload_hash {
            Some(hash) => {
                hasher.update(delimiter_bytes);
                hasher.update(&hash);
            },
            None => {},
        }

        hasher.finalize().into()
    }
}

impl Into<XRPLMessage> for XRPLUserMessage {
    fn into(self) -> XRPLMessage {
        XRPLMessage::UserMessage(self)
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct WithPayload<T: Clone + Into<XRPLMessage>> {
    pub message: T,
    pub payload: Option<nonempty::HexBinary>,
}

impl WithPayload<XRPLUserMessage> {
    pub fn new(message: XRPLUserMessage, payload: Option<nonempty::HexBinary>) -> Self {
        Self {
            message,
            payload,
        }
    }
}

impl<T: Clone + Into<XRPLMessage>> Into<XRPLMessage> for WithPayload<T> {
    fn into(self) -> XRPLMessage {
        self.message.into()
    }
}

pub trait CrossChainMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId;
}

impl CrossChainMessage for Message {
    fn cc_id(&self, _: ChainNameRaw) -> CrossChainId {
        self.cc_id.clone()
    }
}

impl CrossChainMessage for XRPLMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        match self {
            XRPLMessage::ProverMessage(tx_id) => tx_id.cc_id(source_chain),
            XRPLMessage::UserMessage(user_message) => user_message.cc_id(source_chain),
        }
    }
}

impl CrossChainMessage for TxHash {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: format!("0x{}", HexBinary::from(self.clone()).to_hex()).try_into().unwrap(),
        }
    }
}

impl CrossChainMessage for XRPLUserMessage {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: format!("0x{}", HexBinary::from(self.tx_id.clone()).to_hex()).try_into().unwrap(),
        }
    }
}

impl<T: Clone + Into<XRPLMessage>> CrossChainMessage for WithPayload<T> {
    fn cc_id(&self, source_chain: ChainNameRaw) -> CrossChainId {
        self.message.clone().into().cc_id(source_chain)
    }
}
