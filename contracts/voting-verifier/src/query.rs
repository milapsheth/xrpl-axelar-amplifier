use connection_router::state::{CrossChainId, Message};
use cosmwasm_std::{Deps, StdResult};

use crate::error::ContractError;
use crate::execute::MessageStatus;
use crate::state::{VERIFIED_MESSAGES, CONFIRMED_MESSAGE_STATUSES, MessageId};

pub fn verification_statuses(
    deps: Deps,
    messages: Vec<Message>,
) -> StdResult<Vec<(CrossChainId, bool)>> {
    messages
        .into_iter()
        .map(|message| {
            is_message_verified(deps, &message).map(|verified| (message.cc_id, verified))
        })
        .collect::<Result<Vec<(_, _)>, _>>()
        .map_err(Into::into)
}

pub fn is_message_verified(deps: Deps, message: &Message) -> Result<bool, ContractError> {
    match VERIFIED_MESSAGES.may_load(deps.storage, &message.cc_id)? {
        Some(stored) if stored != *message => {
            Err(ContractError::MessageMismatch(message.cc_id.to_string()))
        }
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

pub fn confirmed_message_status(deps: Deps, message_id: &MessageId) -> Result<Option<MessageStatus>, ContractError> {
    match CONFIRMED_MESSAGE_STATUSES.may_load(deps.storage, &message_id)? {
        Some(status) => Ok(Some(status)),
        None => Ok(None),
    }
}

pub fn confirmation_statuses(
    deps: Deps,
    messages: Vec<MessageId>,
) -> StdResult<Vec<(MessageId, Option<MessageStatus>)>> {
    messages
        .into_iter()
        .map(|message_id| {
            confirmed_message_status(deps, &message_id).map(|confirmed_status| (message_id, confirmed_status))
        })
        .collect::<Result<Vec<(_, _)>, _>>()
        .map_err(Into::into)
}
