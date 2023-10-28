use axelar_wasm_std::{nonempty, voting};
use axelar_wasm_std_derive::IntoContractError;
use connection_router;
use connection_router::state::ChainName;
use cosmwasm_std::StdError;
use service_registry;
use thiserror::Error;

use crate::state::MessageId;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    RouterError(#[from] connection_router::ContractError),

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error(transparent)]
    ServiceRegistryError(#[from] service_registry::ContractError),

    #[error("empty batch of messages")]
    EmptyMessages,

    #[error("all messages must have the same source chain {0}")]
    SourceChainMismatch(ChainName),

    #[error("message {0} mismatch with verified message")]
    MessageMismatch(String),

    #[error("invalid message id {0}")]
    InvalidMessageID(String),

    #[error("poll not found")]
    PollNotFound,

    #[error(transparent)]
    VoteError(#[from] voting::Error),

    #[error("worker set already confirmed")]
    WorkerSetAlreadyConfirmed,

    // TODO: include message IDs of mismatched messages in error
    #[error("message ids mismatch with confirmed message")]
    MessageStatusMismatch(Vec<MessageId>),
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
