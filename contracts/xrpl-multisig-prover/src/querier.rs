use std::str::FromStr;

#[cfg(not(feature = "library"))]
use cosmwasm_schema::serde::{de::DeserializeOwned, Serialize};
use cosmwasm_std::{
    to_binary, QueryRequest, WasmQuery, QuerierWrapper, Uint64,
};
use multisig::{key::PublicKey, msg::Multisig};
use axelar_wasm_std::VerificationStatus;

use crate::{
    error::ContractError,
    state::Config,
};

use connection_router::state::{Message, CrossChainId, ChainName};
use service_registry::state::Worker;

pub const XRPL_CHAIN_NAME: &str = "XRPL";

fn query<U, T>(querier: QuerierWrapper, contract_addr: String, query_msg: &T) -> Result<U, ContractError>
where U: DeserializeOwned, T: Serialize + ?Sized {
    querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr,
        msg: to_binary(&query_msg)?,
    })).map_err(ContractError::from)
}

pub struct Querier<'a> {
    querier: QuerierWrapper<'a>,
    config: Config,
}

impl<'a> Querier<'a> {
    pub fn new(querier: QuerierWrapper<'a>, config: Config) -> Self {
        Self {
            querier,
            config,
        }
    }

    pub fn get_active_workers(&self) -> Result<Vec<Worker>, ContractError> {
        query(self.querier, self.config.service_registry_address.to_string(),
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: self.config.service_name.clone(),
                chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
            },
        )
    }

    pub fn get_public_key(&self, worker_address: String) -> Result<PublicKey, ContractError> {
        query(self.querier, self.config.axelar_multisig_address.to_string(),
            &multisig::msg::QueryMsg::GetPublicKey {
                worker_address,
                key_type: self.config.key_type,
            },
        )
    }

    pub fn get_message(&self, message_id: CrossChainId) -> Result<Message, ContractError> {
        let messages: Vec<Message> = query(self.querier, self.config.gateway_address.to_string(),
            &gateway::msg::QueryMsg::GetMessages {
                message_ids: vec![message_id],
            }
        )?;
        Ok(messages[0].clone())
    }

    pub fn get_message_status(&self, message: Message) -> Result<VerificationStatus, ContractError> {
        let statuses: Vec<(CrossChainId, VerificationStatus)> = query(self.querier, self.config.voting_verifier_address.to_string(),
            &voting_verifier::msg::QueryMsg::GetMessagesStatus {
                messages: vec![message],
            }
        )?;
        Ok(statuses[0].1)
    }

    pub fn get_multisig_session(&self, multisig_session_id: Uint64) -> Result<Multisig, ContractError> {
        let query_msg = multisig::msg::QueryMsg::GetMultisig {
            session_id: multisig_session_id,
        };
        query(self.querier, self.config.axelar_multisig_address.to_string(), &query_msg)
    }

    pub fn get_next_multisig_session_id(&self) -> Result<Uint64, ContractError> {
        query(self.querier, self.config.axelar_multisig_address.to_string(),
            &multisig::msg::QueryMsg::GetNextSessionId,
        )
    }
}
