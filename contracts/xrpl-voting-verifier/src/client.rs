use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::{Addr, WasmMsg};
use error_stack::ResultExt;

use crate::msg::{ExecuteMsg, MessageStatus, PollResponse, QueryMsg, XRPLMessage};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query the voting verifier contract at {0}")]
    QueryVotingVerifier(Addr),
}

impl<'a> From<client::Client<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::Client<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::Client<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> Client<'a> {
    pub fn verify_messages(&self, messages: Vec<XRPLMessage>) -> Option<WasmMsg> {
        if messages.is_empty() {
            return None;
        }
        Some(self.client.execute(&ExecuteMsg::VerifyMessages(messages)))
    }

    pub fn vote(&self, poll_id: PollId, votes: Vec<Vote>) -> WasmMsg {
        self.client.execute(&ExecuteMsg::Vote { poll_id, votes })
    }

    pub fn end_poll(&self, poll_id: PollId) -> WasmMsg {
        self.client.execute(&ExecuteMsg::EndPoll { poll_id })
    }

    pub fn update_voting_threshold(&self, new_voting_threshold: MajorityThreshold) -> WasmMsg {
        self.client.execute(&ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        })
    }

    pub fn poll(&self, poll_id: PollId) -> Result<PollResponse> {
        self.client
            .query(&QueryMsg::Poll { poll_id })
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }

    pub fn messages_status(&self, messages: Vec<XRPLMessage>) -> Result<Vec<MessageStatus>> {
        match messages.as_slice() {
            [] => Ok(vec![]),
            _ => self
                .client
                .query(&QueryMsg::MessagesStatus(messages))
                .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone())),
        }
    }

    pub fn current_threshold(&self) -> Result<MajorityThreshold> {
        self.client
            .query(&QueryMsg::CurrentThreshold)
            .change_context_lazy(|| Error::QueryVotingVerifier(self.client.address.clone()))
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::{Threshold, VerificationStatus};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
    use cosmwasm_std::{from_json, Addr, DepsMut, QuerierWrapper, Uint64, WasmQuery};
    use xrpl_multisig_prover::types::XRPLPaymentAmount;

    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, MessageStatus, QueryMsg, UserMessage, XRPLMessage};
    use crate::Client;

    #[test]
    fn query_messages_status() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        let msg_1 = XRPLMessage::UserMessage(UserMessage {
            tx_id: [0; 32],
            source_address: "0x1234".parse().unwrap(),
            destination_address: "0x5678".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
            amount: XRPLPaymentAmount::Drops(100),
        });

        let msg_2 = XRPLMessage::UserMessage(UserMessage {
            tx_id: [1; 32],
            source_address: "0x4321".parse().unwrap(),
            destination_address: "0x8765".parse().unwrap(),
            destination_chain: "eth".parse().unwrap(),
            payload_hash: [0; 32],
            amount: XRPLPaymentAmount::Drops(200),
        });

        assert!(client.messages_status(vec![]).unwrap().is_empty());
        assert_eq!(
            client
                .messages_status(vec![msg_1.clone(), msg_2.clone()])
                .unwrap(),
            vec![
                MessageStatus::new(msg_1, VerificationStatus::Unknown),
                MessageStatus::new(msg_2, VerificationStatus::Unknown)
            ]
        );
    }

    #[test]
    fn query_current_threshold() {
        let (querier, instantiate_msg, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();

        assert_eq!(
            client.current_threshold().unwrap(),
            instantiate_msg.voting_threshold
        );
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let addr = "voting-verifier";
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_contract(deps.as_mut());

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, Addr::unchecked(addr))
    }

    fn instantiate_contract(deps: DepsMut) -> InstantiateMsg {
        let env = mock_env();
        let info = mock_info("deployer", &[]);

        let msg = InstantiateMsg {
            governance_address: "governance".try_into().unwrap(),
            service_registry_address: "service-registry".try_into().unwrap(),
            service_name: "voting-verifier".try_into().unwrap(),
            source_gateway_address: "source-gateway".try_into().unwrap(),
            voting_threshold: Threshold::try_from((Uint64::new(2), Uint64::new(3)))
                .unwrap()
                .try_into()
                .unwrap(),
            block_expiry: 100.try_into().unwrap(),
            confirmation_height: 10,
            rewards_address: "rewards".try_into().unwrap(),
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
