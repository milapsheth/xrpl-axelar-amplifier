use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use axelar_wasm_std::VerificationStatus;
use interchain_token_service::TokenId;
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
use sha3::Keccak256;

use axelar_wasm_std::Participant;
use cosmwasm_std::Addr;
use axelar_wasm_std::nonempty;

use crate::error::XRPLError;
use crate::msg::xrpl_account_id_hex;

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

pub const XRPL_MESSAGE_ID_FORMAT: axelar_wasm_std::msg_id::MessageIdFormat = axelar_wasm_std::msg_id::MessageIdFormat::HexTxHash;

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
#[derive(Eq, Hash)]
pub struct XRPLToken {
    #[serde(with = "xrpl_account_id_hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub issuer: XRPLAccountId,
    pub currency: XRPLCurrency,
}

#[cw_serde]
pub enum XRPLTokenOrXRP {
    Token(XRPLToken),
    XRP,
}

#[cw_serde]
pub struct XRPLRemoteInterchainTokenInfo { // TODO: rename
    pub xrpl_token: XRPLToken,
    pub canonical_decimals: u8,
}

const ITS_INTERCHAIN_TOKEN_ID: &[u8] = "its-interchain-token-id".as_bytes();

impl XRPLTokenOrXRP {
    pub fn token_id(&self) -> TokenId {
        let (deployer, salt) = match self {
            XRPLTokenOrXRP::Token(token) => {
                (token.issuer.to_bytes(), token.currency.clone().to_bytes().to_vec())
            },
            XRPLTokenOrXRP::XRP => ([0u8; 20], "XRP".as_bytes().to_vec()),
        };
        let prefix = Keccak256::digest(ITS_INTERCHAIN_TOKEN_ID);
        let token_id = Keccak256::digest(vec![prefix.as_slice(), &deployer, salt.as_slice()].concat());
        let token_id_slice: &[u8; 32] = token_id.as_ref();
        TokenId::new(token_id_slice.clone())
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
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

impl From<XRPLMemo> for HexBinary {
    fn from(memo: XRPLMemo) -> Self {
        memo.0
    }
}

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
    TrustSet(XRPLTrustSetTx),
}

impl XRPLUnsignedTx {
    pub fn sequence(&self) -> &XRPLSequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => &tx.sequence,
            XRPLUnsignedTx::TicketCreate(tx) => &tx.sequence,
            XRPLUnsignedTx::SignerListSet(tx) => &tx.sequence,
            XRPLUnsignedTx::TrustSet(tx) => &tx.sequence,
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
            XRPLUnsignedTx::TrustSet(tx) => match tx.sequence {
                XRPLSequence::Plain(_) => 1,
                XRPLSequence::Ticket(_) => 0,
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
    pub cross_currency: Option<XRPLCrossCurrencyOptions>,
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
#[derive(Eq, Hash)]
#[serde(transparent)]
pub struct XRPLAccountId([u8; 20]);

impl XRPLAccountId {
    pub const fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8; 20]> for XRPLAccountId {
    fn as_ref(&self) -> &[u8; 20] {
        &self.0
    }
}

impl From<[u8; 20]> for XRPLAccountId {
    fn from(bytes: [u8; 20]) -> Self {
        XRPLAccountId(bytes)
    }
}

#[test]
fn test_xrpl_account_id_from_string() {
    let xrpl_account = "rNM8ue6DZpneFC4gBEJMSEdbwNEBZjs3Dy";
    assert_eq!(XRPLAccountId::from_str(xrpl_account).unwrap().to_bytes(), [146, 136, 70, 186, 245, 155, 212, 140, 40, 177, 49, 133, 84, 114, 208, 76, 147, 187, 208, 183]);
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
            .map_err(|_| XRPLError::InvalidAddress(address.to_string()))?;

        if res.len() != 25 {
            return Err(XRPLError::InvalidAddress(address.to_string()));
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
#[derive(Eq, Hash)]
pub struct XRPLCurrency(String);

impl XRPLCurrency {
    pub fn to_bytes(self) -> [u8; 20] {
        let mut buffer = [0u8; 20];
        buffer[12..15].copy_from_slice(self.to_string().as_bytes());
        buffer
    }
}

impl From<XRPLCurrency> for [u8; 20] {
    fn from(currency: XRPLCurrency) -> [u8; 20] {
        currency.to_bytes()
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
#[derive(Eq, Hash)]
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

impl TryFrom<String> for XRPLTokenAmount {
    type Error = XRPLError;

    fn try_from(s: String) -> Result<XRPLTokenAmount, XRPLError> {
        let exp_separator: &[_] = &['e', 'E'];

        let (base_part, exponent_value) = match s.find(exp_separator) {
            None => (s.as_str(), 0),
            Some(loc) => {
                let (base, exp) = (&s[..loc], &s[loc + 1..]);
                (base, i64::from_str(exp).map_err(|_| XRPLError::InvalidAmount { reason: "invalid exponent".to_string() })?)
            }
        };

        if base_part.is_empty() {
            return Err(XRPLError::InvalidAmount { reason: "base part empty".to_string() });
        }

        let (mut digits, decimal_offset): (String, _) = match base_part.find('.') {
            None => (base_part.to_string(), 0),
            Some(loc) => {
                let (lead, trail) = (&base_part[..loc], &base_part[loc + 1..]);
                let mut digits = String::from(lead);
                digits.push_str(trail);
                let trail_digits = trail.chars().filter(|c| *c != '_').count();
                (digits, trail_digits as i64)
            }
        };

        let exponent = match decimal_offset.checked_sub(exponent_value) {
            Some(exponent) => exponent,
            None => {
                return Err(XRPLError::InvalidAmount { reason: "overflow".to_string() });
            }
        };

        if digits.starts_with('-') {
            return Err(XRPLError::InvalidAmount { reason: "negative amount".to_string() });
        }

        if digits.starts_with('+') {
            digits = digits[1..].to_string();
        }

        let mantissa = Uint128::from_str(digits.as_str()).map_err(|e| XRPLError::InvalidAmount { reason: e.to_string() })?;

        let (mantissa, exponent) = canonicalize_mantissa(mantissa, exponent * -1)?;

        Ok(XRPLTokenAmount::new(mantissa, exponent))
    }
}

#[cw_serde]
pub struct XRPLCrossCurrencyOptions {
    pub send_max: XRPLPaymentAmount,
    pub paths: Option<XRPLPathSet>,
}

#[cw_serde]
pub struct XRPLPathSet {
    pub paths: Vec<XRPLPath>,
}

#[cw_serde]
pub struct XRPLPath {
    pub steps: Vec<XRPLPathStep>,
}

#[cw_serde]
pub enum XRPLPathStep {
    Account(XRPLAccountId),
    Currency(XRPLCurrency),
    XRP,
    Issuer(XRPLAccountId),
    Token(XRPLToken),
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(
    mut mantissa: Uint128,
    mut exponent: i64,
) -> Result<(u64, i64), XRPLError> {
    let ten = Uint128::from(10u128);

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa *= ten;
        exponent -= 1;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent > MAX_EXPONENT {
            return Err(XRPLError::InvalidAmount {
                reason: "overflow".to_string(),
            });
        }
        mantissa /= ten;
        exponent += 1;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok((0, 1));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA.into() {
        return Err(XRPLError::InvalidAmount {
            reason: format!("overflow exponent {} mantissa {}", exponent, mantissa).to_string(),
        });
    }

    let mantissa = u64::from_be_bytes(mantissa.to_be_bytes()[8..].try_into().unwrap());

    Ok((mantissa, exponent))
}
