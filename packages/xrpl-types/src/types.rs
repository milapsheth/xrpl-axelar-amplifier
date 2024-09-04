use std::fmt;
use std::fmt::Display;

use axelar_wasm_std::VerificationStatus;
use router_api::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_json, Binary, HexBinary, StdResult, Uint128, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use k256::ecdsa;
use k256::schnorr::signature::SignatureEncoding;
use multisig::key::PublicKey;
use multisig::key::Signature;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::error::XRPLError;
use axelar_wasm_std::Participant;
use cosmwasm_std::Addr;
use axelar_wasm_std::nonempty;

#[cw_serde]
#[derive(Eq, Ord, PartialOrd)]
pub struct AxelarSigner {
    pub address: Addr,
    pub weight: u16,
    pub pub_key: PublicKey,
}

impl From<AxelarSigner> for Participant {
    fn from(signer: AxelarSigner) -> Self {
        let weight = nonempty::Uint128::try_from(Uint128::from(u128::from(signer.weight))).unwrap();
        Self {
            address: signer.address,
            weight,
        }
    }
}

#[cw_serde]
pub enum TransactionStatus {
    Pending,
    Succeeded,
    FailedOnChain,
    Inconclusive,
}

#[cw_serde]
pub struct TxHash(pub HexBinary);

pub const XRPL_MESSAGE_ID_FORMAT: axelar_wasm_std::msg_id::MessageIdFormat = axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex;

impl TryFrom<CrossChainId> for TxHash {
    type Error = XRPLError;
    fn try_from(cc_id: CrossChainId) -> Result<Self, XRPLError> {
        Ok(Self(HexBinary::from_hex(
            cc_id.message_id.to_ascii_lowercase().as_str(),
        )?))
    }
}

impl From<TxHash> for HexBinary {
    fn from(hash: TxHash) -> Self {
        hash.0
    }
}

impl From<VerificationStatus> for TransactionStatus {
    fn from(status: VerificationStatus) -> TransactionStatus {
        match status {
            VerificationStatus::SucceededOnSourceChain => TransactionStatus::Succeeded,
            VerificationStatus::FailedOnSourceChain => TransactionStatus::FailedOnChain,
            _ => TransactionStatus::Inconclusive,
        }
    }
}

#[cw_serde]
pub struct TransactionInfo {
    pub status: TransactionStatus,
    pub unsigned_contents: XRPLUnsignedTx,
    pub original_message_id: Option<CrossChainId>,
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
        from_json(Binary::from(value))
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
    pub issuer: XRPLAccountId,
    pub currency: XRPLCurrency,
}

#[cw_serde]
pub enum XRPLPaymentAmount {
    Drops(u64),
    Token(XRPLToken, XRPLTokenAmount),
}

// TODO: delete this
impl Display for XRPLPaymentAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            XRPLPaymentAmount::Drops(drops) => write!(f, "Drops({})", drops),
            XRPLPaymentAmount::Token(token, amount) => write!(f, "TokenAmount({:?},{:?})", token, amount),
        }
    }
}

#[cw_serde]
pub struct XRPLMemo(pub HexBinary);


#[cw_serde]
pub enum XRPLSequence {
    Plain(u32),
    Ticket(u32),
}

impl From<XRPLSequence> for u32 {
    fn from(value: XRPLSequence) -> Self {
        match value {
            XRPLSequence::Plain(sequence) => sequence,
            XRPLSequence::Ticket(ticket) => ticket,
        }
    }
}

#[cw_serde]
pub struct XRPLSignerEntry {
    pub account: XRPLAccountId,
    pub signer_weight: u16,
}

impl From<AxelarSigner> for XRPLSignerEntry {
    fn from(signer: AxelarSigner) -> Self {
        Self {
            account: XRPLAccountId::from(&signer.pub_key),
            signer_weight: signer.weight,
        }
    }
}

#[cw_serde]
pub enum XRPLUnsignedTx {
    Payment(XRPLPaymentTx),
    SignerListSet(XRPLSignerListSetTx),
    TicketCreate(XRPLTicketCreateTx),
}

impl XRPLUnsignedTx {
    pub fn sequence(&self) -> &XRPLSequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => &tx.sequence,
            XRPLUnsignedTx::TicketCreate(tx) => &tx.sequence,
            XRPLUnsignedTx::SignerListSet(tx) => &tx.sequence,
        }
    }
    pub fn sequence_number_increment(&self, status: TransactionStatus) -> u32 {
        if status == TransactionStatus::Pending || status == TransactionStatus::Inconclusive {
            return 0;
        }

        match self {
            XRPLUnsignedTx::Payment(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
            XRPLUnsignedTx::SignerListSet(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
            },
            XRPLUnsignedTx::TicketCreate(tx) => match status {
                TransactionStatus::Succeeded => tx.ticket_count + 1,
                TransactionStatus::FailedOnChain => 1,
                TransactionStatus::Inconclusive | TransactionStatus::Pending => unreachable!(),
            },
        }
    }
}

#[cw_serde]
pub struct XRPLPaymentTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
    pub amount: XRPLPaymentAmount,
    pub destination: XRPLAccountId,
}

#[cw_serde]
pub struct XRPLSignerListSetTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
    pub signer_quorum: u32,
    pub signer_entries: Vec<XRPLSignerEntry>,
}

#[cw_serde]
pub struct XRPLTicketCreateTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
    pub ticket_count: u32,
}

#[cw_serde]
pub struct XRPLTrustSetTx {
    pub token: XRPLToken,
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: XRPLSequence,
}

#[cw_serde]
pub struct XRPLAccountId([u8; 20]);

impl XRPLAccountId {
    pub const fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl Display for XRPLAccountId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut payload = Vec::<u8>::with_capacity(25);
        payload.extend(&[0x00]);
        payload.extend_from_slice(&self.to_bytes());

        let checksum_hash1 = Sha256::digest(payload.clone());
        let checksum_hash2 = Sha256::digest(checksum_hash1);
        let checksum = &checksum_hash2[0..4];

        payload.extend(checksum);

        let str = bs58::encode(payload)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_string();

        write!(f, "{}", str)
    }
}

impl From<&PublicKey> for XRPLAccountId {
    fn from(pub_key: &PublicKey) -> Self {
        let public_key_hex: HexBinary = pub_key.clone().into();

        assert!(public_key_hex.len() == 33);

        let public_key_inner_hash = Sha256::digest(public_key_hex);
        let account_id = Ripemd160::digest(public_key_inner_hash);

        XRPLAccountId(account_id.into())
    }
}

impl std::str::FromStr for XRPLAccountId {
    type Err = XRPLError;

    fn from_str(address: &str) -> Result<Self, XRPLError> {
        let res = bs58::decode(address)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_vec()
            .map_err(|_| XRPLError::InvalidAddress)?;
        // .map_err(|_| XRPLError::InvalidAddress)?;
        if res.len() != 25 {
            return Err(XRPLError::InvalidAddress);
        }
        let mut buffer = [0u8; 20];
        buffer.copy_from_slice(&res[1..21]);
        Ok(XRPLAccountId(buffer))
    }
}

#[cw_serde]
pub struct XRPLSigner {
    pub account: XRPLAccountId,
    pub txn_signature: HexBinary,
    pub signing_pub_key: PublicKey,
}

impl TryFrom<(multisig::key::Signature, multisig::msg::Signer)> for XRPLSigner {
    type Error = XRPLError;

    fn try_from(
        (signature, axelar_signer): (multisig::key::Signature, multisig::msg::Signer),
    ) -> Result<Self, XRPLError> {
        let txn_signature = match axelar_signer.pub_key {
            multisig::key::PublicKey::Ecdsa(_) => {
                HexBinary::from(
                    ecdsa::Signature::to_der(
                        &ecdsa::Signature::try_from(signature.as_ref())
                            .map_err(|_| XRPLError::FailedToEncodeSignature)?,
                    )
                    .to_vec(),
                )
            },
            _ => unimplemented!("Unsupported public key type"),
        };

        Ok(XRPLSigner {
            account: XRPLAccountId::from(&axelar_signer.pub_key),
            signing_pub_key: axelar_signer.pub_key.clone(),
            txn_signature,
        })
    }
}

#[cw_serde]
pub struct XRPLSignedTransaction {
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>,
}

impl XRPLSignedTransaction {
    pub fn new(unsigned_tx: XRPLUnsignedTx, signers: Vec<XRPLSigner>) -> Self {
        Self {
            unsigned_tx,
            signers,
        }
    }
}

#[cw_serde]
pub struct XRPLCurrency(String);

impl XRPLCurrency {
    pub fn to_bytes(self) -> [u8; 20] {
        let mut buffer = [0u8; 20];
        buffer[12..15].copy_from_slice(self.to_string().as_bytes());
        buffer
    }
}

impl Display for XRPLCurrency {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

const ALLOWED_CURRENCY_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789?!@#$%^&*<>(){}[]|";

impl TryFrom<String> for XRPLCurrency {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<XRPLCurrency, XRPLError> {
        if s.len() != 3 || s == "XRP" || !s.chars().all(|c| ALLOWED_CURRENCY_CHARS.contains(c)) {
            return Err(XRPLError::InvalidCurrency);
        }
        Ok(XRPLCurrency(s))
    }
}

pub const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
pub const MAX_MANTISSA: u64 = 10_000_000_000_000_000 - 1;
pub const MIN_EXPONENT: i64 = -96;
pub const MAX_EXPONENT: i64 = 80;

// XRPLTokenAmount always in canonicalized XRPL mantissa-exponent format,
// such that MIN_MANTISSA <= mantissa <= MAX_MANTISSA (or equal to zero), MIN_EXPONENT <= exponent <= MAX_EXPONENT,
// In XRPL generally it can be decimal and even negative (!) but in our case that doesn't apply.
#[cw_serde]
pub struct XRPLTokenAmount {
    mantissa: u64,
    exponent: i64,
}

impl XRPLTokenAmount {
    pub const MAX: XRPLTokenAmount = XRPLTokenAmount {
        mantissa: MAX_MANTISSA,
        exponent: MAX_EXPONENT,
    };

    pub fn new(mantissa: u64, exponent: i64) -> Self {
        assert!(
            mantissa == 0
                || ((MIN_MANTISSA..=MAX_MANTISSA).contains(&mantissa)
                    && (MIN_EXPONENT..=MAX_EXPONENT).contains(&exponent))
        );
        Self { mantissa, exponent }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        if self.mantissa == 0 {
            0x8000000000000000u64.to_be_bytes()
        } else {
            // not xrp-bit | positive bit | 8 bits exponent | 54 bits mantissa
            (0xC000000000000000u64 | ((self.exponent + 97) as u64) << 54 | self.mantissa)
                .to_be_bytes()
        }
    }
}
