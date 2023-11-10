use axelar_wasm_std::{Participant, Snapshot};
use connection_router::state::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, HexBinary, StdResult, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::key::{PublicKey, Signature};

use crate::contract::XRPLUnsignedPaymentTransaction;

#[cw_serde]
pub enum TransactionStatus {
    Pending,
    Succeeded,
    Failed,
}

#[cw_serde]
pub struct TxHash(pub HexBinary);

#[cw_serde]
pub struct TransactionInfo {
    pub sequence_number: u32,
    pub status: TransactionStatus,
    pub unsigned_contents: XRPLUnsignedPaymentTransaction,
    pub message_id: CrossChainId,
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

pub struct WorkersInfo {
    pub snapshot: Snapshot,
    pub pubkeys_by_participant: Vec<(Participant, PublicKey)>,
}

#[cw_serde]
pub struct XRPLToken {
    pub issuer: String,
    pub currency: String,
}

impl XRPLToken {
    pub const NATIVE_CURRENCY: &str = "XRP";
}
