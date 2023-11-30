use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, HexBinary, StdResult, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::key::Signature;
use voting_verifier::{state::MessageId, execute::MessageStatus};

use crate::xrpl_multisig::XRPLUnsignedTx;

#[cw_serde]
pub enum TransactionStatus {
    Pending,
    Succeeded,
    FailedOnChain,
    FailedOffChain,
}

#[cw_serde]
pub struct TxHash(pub HexBinary);

impl Into<HexBinary> for TxHash {
    fn into(self) -> HexBinary {
        self.0
    }
}

impl Into<MessageId> for TxHash {
    fn into(self) -> MessageId {
        MessageId(nonempty::String::try_from(self.0.to_hex()).unwrap())
    }
}

impl Into<TransactionStatus> for MessageStatus {
    fn into(self) -> TransactionStatus {
        match self {
            MessageStatus::Success => TransactionStatus::Succeeded,
            MessageStatus::FailureOnChain => TransactionStatus::FailedOnChain,
            MessageStatus::FailureOffChain => TransactionStatus::FailedOffChain,
        }
    }
}

#[cw_serde]
pub struct TransactionInfo {
    pub status: TransactionStatus,
    // TODO: save the hash of the transaction
    pub unsigned_contents: XRPLUnsignedTx,
}

impl From<HexBinary> for TxHash {
    fn from(id: HexBinary) -> Self {
        Self(id)
    }
}

impl From<&[u8]> for TxHash {
    fn from(id: &[u8]) -> Self {
        Self(id.into())
    }
}

impl<'a> PrimaryKey<'a> for TxHash {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = TxHash;
    type SuperSuffix = TxHash;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl KeyDeserialize for TxHash {
    type Output = TxHash;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(from_binary(&value.into()).expect("violated invariant: TxHash is not deserializable"))
    }
}

#[cw_serde]
#[derive(Ord, PartialOrd, Eq)]
pub struct Operator {
    pub address: HexBinary,
    pub weight: Uint256,
    pub signature: Option<Signature>,
}

impl Operator {
    pub fn with_signature(self, sig: Signature) -> Operator {
        Operator {
            address: self.address,
            weight: self.weight,
            signature: Some(sig),
        }
    }
}

#[cw_serde]
pub struct XRPLToken {
    pub issuer: String,
    pub currency: String,
}

impl XRPLToken {
    pub const NATIVE_CURRENCY: &str = "XRP";
}
