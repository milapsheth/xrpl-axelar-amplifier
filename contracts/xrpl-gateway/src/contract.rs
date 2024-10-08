use std::fmt::Debug;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use crate::msg::{ExecuteMsg, QueryMsg};
use router_api::CrossChainId;

use crate::msg::InstantiateMsg;

mod execute;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(internal::instantiate(deps, env, info, msg)?)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let msg = msg.ensure_permissions(deps.storage, &info.sender)?;
    Ok(internal::execute(deps, env, info, msg)?)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    Ok(internal::query(deps, env, msg)?)
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gateway contract config is missing")]
    ConfigMissing,
    #[error("invalid store access")]
    InvalidStoreAccess,
    #[error("failed to serialize the response")]
    SerializeResponse,
    #[error("batch contains duplicate message ids")]
    DuplicateMessageIds,
    #[error("invalid address")]
    InvalidAddress,
    #[error("failed to query message status")]
    MessageStatus,
    #[error("message with ID {0} not found")]
    MessageNotFound(CrossChainId),
    #[error("message with id {0} mismatches with the stored one")]
    MessageMismatch(CrossChainId),
    #[error("router only")]
    RouterOnly,
    #[error("invalid message with ID {0}")]
    InvalidMessage(CrossChainId),
    #[error("invalid cross-chain id")]
    InvalidCrossChainId,
    #[error("unable to generate event index")]
    EventIndex,
    #[error("caller does not have the required permissions")]
    InvalidPermissions,
}

mod internal {
    use axelar_wasm_std::address;
    use client::Client;
    use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};
    use error_stack::{Result, ResultExt};
    use crate::msg::{ExecuteMsg, QueryMsg};
    use router_api::client::Router;

    use crate::contract::Error;
    use crate::msg::InstantiateMsg;
    use crate::state::Config;
    use crate::{contract, state};

    pub(crate) fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, Error> {
        let router = address::validate_cosmwasm_address(deps.api, &msg.router_address)
            .change_context(Error::InvalidAddress)?;
        let verifier = address::validate_cosmwasm_address(deps.api, &msg.verifier_address)
            .change_context(Error::InvalidAddress)?;
        let its_hub = address::validate_cosmwasm_address(deps.api, &msg.its_hub_address)
            .change_context(Error::InvalidAddress)?;

        state::save_config(deps.storage, &Config {
            verifier,
            router,
            its_hub,
            axelar_chain_name: msg.axelar_chain_name,
            xrpl_chain_name: msg.xrpl_chain_name,
            xrpl_multisig_address: msg.xrpl_multisig_address,
        })
            .change_context(Error::InvalidStoreAccess)?;

        Ok(Response::new())
    }

    pub(crate) fn execute(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        msg: ExecuteMsg,
    ) -> Result<Response, Error> {
        let config = state::load_config(deps.storage).change_context(Error::ConfigMissing)?;
        let verifier = Client::new(deps.querier, &config.verifier).into();

        let router = Router {
            address: config.router,
        };

        match msg.ensure_permissions(deps.storage, &info.sender).map_err(|_| Error::InvalidPermissions)? {
            ExecuteMsg::DeployXrpToSidechain {
                sidechain_name,
                params,
            } => contract::execute::deploy_xrp_to_sidechain(
                deps.storage,
                env.block.height,
                &router,
                &config.its_hub,
                &config.axelar_chain_name,
                &config.xrpl_chain_name,
                &sidechain_name,
                &config.xrpl_multisig_address,
                params,
            ),
            ExecuteMsg::DeployInterchainToken(params) => contract::execute::deploy_interchain_token(
                deps.storage,
                env.block.height,
                &router,
                &config.its_hub,
                &config.axelar_chain_name,
                &config.xrpl_chain_name,
                &config.xrpl_multisig_address,
                params,
            ),
            ExecuteMsg::VerifyMessages(msgs) => contract::execute::verify_messages(&verifier, msgs),
            // Should be called RouteOutgoingMessage.
            // Called RouteMessages for compatibility with the router.
            ExecuteMsg::RouteMessages(msgs) => {
                if info.sender != router.address {
                    return Err(Error::RouterOnly)?;
                }

                contract::execute::route_outgoing_messages(deps.storage, msgs, config.its_hub, config.axelar_chain_name)
            },
            ExecuteMsg::RouteIncomingMessages(msgs) => contract::execute::route_incoming_messages(
                deps.storage,
                &verifier,
                &router,
                msgs,
                &config.its_hub,
                &config.axelar_chain_name,
                &config.xrpl_multisig_address,
            ),
        }
    }

    pub(crate) fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, Error> {
        match msg {
            QueryMsg::OutgoingMessages(message_ids) => {
                let msgs = contract::query::outgoing_messages(deps.storage, message_ids)?;
                to_json_binary(&msgs).change_context(Error::SerializeResponse)
            }
        }
    }
}
