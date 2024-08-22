use axelar_wasm_std::nonempty;
use axelar_wasm_std_derive::IntoContractError;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("invalid amount: {reason}")]
    InvalidAmount { reason: String },

    #[error("serialization failed")]
    SerializationFailed,

    #[error("invalid contract reply: {reason}")]
    InvalidContractReply { reason: String },

    #[error("caller is not authorized")]
    Unauthorized,

    #[error("chain name is invalid")]
    InvalidChainName,

    #[error(transparent)]
    ServiceRegistryError(#[from] service_registry::ContractError),

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error("verifier set has not changed sufficiently since last update")]
    VerifierSetUnchanged,

    #[error("ticket count threshold has not been reached")]
    TicketCountThresholdNotReached,

    #[error("transaction status is already updated")]
    TransactionStatusAlreadyUpdated,

    #[error("previous ticket create transaction is pending")]
    PreviousTicketCreateTxPending,

    #[error("invalid message status")]
    InvalidMessageStatus,

    #[error("transaction has not been confirmed")]
    TransactionStatusNotConfirmed,

    #[error("transaction status is not pending")]
    TransactionStatusNotPending,

    #[error("invalid payment amount")]
    InvalidPaymentAmount,

    #[error("invalid signing threshold")]
    InvalidSigningThreshold,

    #[error("verifier set is not set")]
    VerifierSetIsNotSet,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid currency")]
    InvalidCurrency,

    #[error("invalid signing pub key")]
    InvalidSigningPubKey,

    #[error("invalid transaction signature")]
    InvalidSignature,

    #[error("signing session not completed")]
    SigningSessionNotCompleted,

    #[error("invalid blob")]
    InvalidBlob,

    #[error("invalid message ID {0}")]
    InvalidMessageID(String),

    #[error("failed to encode signature")]
    FailedToEncodeSignature,

    #[error("failed to serialize")]
    FailedToSerialize,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("signature not found")]
    SignatureNotFound,

    #[error("invalid message source address")]
    InvalidMessageSourceAddress,

    #[error("invalid message destination address")]
    InvalidMessageDestinationAddress,

    #[error("payment already has active signing session with ID {0}")]
    PaymentAlreadyHasActiveSigningSession(u64),

    #[error("invalid token denomination")]
    InvalidTokenDenom,

    #[error("no available tickets")]
    NoAvailableTickets,

    #[error("no verifier set stored")]
    NoVerifierSet,

    #[error("generic error {0}")]
    GenericError(String),
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
