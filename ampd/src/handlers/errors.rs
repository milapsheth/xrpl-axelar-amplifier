use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to get the latest finalized block")]
    Finalizer,
    #[error("failed to deserialize the event")]
    DeserializeEvent,
    #[error("failed to get signature from tofnd")]
    Sign,
    #[error("failed to get transaction receipts")]
    TxReceipts,
    #[error("failed to parse public key")]
    PublicKey, // TODO: check if redundant
    #[error("failed to prepare message for signing")]
    MessageToSign, // TODO: check if redundant
    #[error("unsupported key type {0}")]
    KeyType(String),
}
