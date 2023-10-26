use connection_router::state::Message;
use cosmwasm_std::{
    entry_point, DepsMut, Empty, Env, MessageInfo, Response, StdResult
};

use gateway::error::ContractError;
use gateway::events::GatewayEvent;
use crate::msg::ExecuteMsg;

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> StdResult<Response> {
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::VerifyMessages(_) => todo!(),
        ExecuteMsg::RouteMessages(msgs) => route_messages(msgs),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

pub fn route_messages(msgs: Vec<Message>) -> Result<Response, ContractError> {
    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::MessageRouted { msg }.into()),
    ))
}
