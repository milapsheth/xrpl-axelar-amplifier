use std::str::FromStr;

use axelar_wasm_std::VerificationStatus;
use router_api::{ChainName, CrossChainId, Message};
use cosmwasm_schema::serde::{de::DeserializeOwned, Serialize};
use cosmwasm_std::{to_json_binary, QuerierWrapper, QueryRequest, Uint64, WasmQuery};
use multisig::{key::PublicKey, multisig::Multisig};
use voting_verifier::msg::MessageStatus;

use crate::{error::ContractError, state::Config};

use service_registry::state::{Service, WeightedVerifier};

pub const XRPL_CHAIN_NAME: &str = "XRPL";

fn query<U, T>(
    querier: QuerierWrapper,
    contract_addr: String,
    query_msg: &T,
) -> Result<U, ContractError>
where
    U: DeserializeOwned,
    T: Serialize + ?Sized,
{
    querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr,
            msg: to_json_binary(&query_msg)?,
        }))
        .map_err(ContractError::from)
}

pub struct Querier<'a> {
    querier: QuerierWrapper<'a>,
    config: Config,
}

impl<'a> Querier<'a> {
    pub fn new(querier: QuerierWrapper<'a>, config: Config) -> Self {
        Self { querier, config }
    }

    pub fn get_service(&self) -> Result<Service, ContractError> {
        query(
            self.querier,
            self.config.service_registry.to_string(),
            &service_registry::msg::QueryMsg::Service {
                service_name: self.config.service_name.clone(),
            },
        )
    }

    pub fn get_active_verifiers(&self) -> Result<Vec<WeightedVerifier>, ContractError> {
        query(
            self.querier,
            self.config.service_registry.to_string(),
            &service_registry::msg::QueryMsg::ActiveVerifiers {
                service_name: self.config.service_name.clone(),
                chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
            },
        )
    }

    pub fn get_public_key(&self, verifier_address: String) -> Result<PublicKey, ContractError> {
        query(
            self.querier,
            self.config.axelar_multisig.to_string(),
            &multisig::msg::QueryMsg::PublicKey {
                verifier_address,
                key_type: self.config.key_type,
            },
        )
    }

    pub fn get_message(&self, message_id: &CrossChainId) -> Result<Message, ContractError> {
        let messages: Vec<Message> = query(
            self.querier,
            self.config.gateway.to_string(),
            &gateway_api::msg::QueryMsg::OutgoingMessages(
                vec![message_id.clone()],
            ),
        )?;
        messages
            .first()
            .cloned()
            .ok_or(ContractError::InvalidMessageID(message_id.message_id.to_string()))
    }

    pub fn get_message_status(
        &self,
        message: Message,
    ) -> Result<VerificationStatus, ContractError> {
        let messages_status: Vec<MessageStatus> = query(
            self.querier,
            self.config.voting_verifier.to_string(),
            &voting_verifier::msg::QueryMsg::MessagesStatus(
                vec![message],
            ),
        )?;
        let message_status = messages_status.first().ok_or(ContractError::MessageStatusNotFound)?;
        Ok(message_status.status)
    }

    pub fn get_multisig_session(
        &self,
        multisig_session_id: &Uint64,
    ) -> Result<Multisig, ContractError> {
        let query_msg = multisig::msg::QueryMsg::Multisig {
            session_id: *multisig_session_id,
        };
        query(
            self.querier,
            self.config.axelar_multisig.to_string(),
            &query_msg,
        )
    }

    pub fn get_verifier_set_status(
        &self,
        verifier_set: &crate::axelar_workers::VerifierSet,
    ) -> Result<VerificationStatus, ContractError> {
        let query_msg = voting_verifier::msg::QueryMsg::VerifierSetStatus(verifier_set.clone().into());
        query(
            self.querier,
            self.config.voting_verifier.to_string(),
            &query_msg,
        )
    }
}
