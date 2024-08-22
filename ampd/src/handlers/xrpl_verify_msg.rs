use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::str::FromStr;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use router_api::ChainName;
use serde::Deserialize;
use axelar_wasm_std::voting::{PollId, Vote};
use tokio::sync::watch::Receiver;
use valuable::Valuable;

use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;
use events::Error::EventTypeMismatch;
use tracing::{info, info_span};
use xrpl_multisig_prover::querier::XRPL_CHAIN_NAME;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::types::{Hash, TMAddress};
use crate::xrpl::json_rpc::XRPLClient;
use crate::xrpl::verifier::verify_message;
use crate::xrpl::types::XRPLAddress;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: Hash,
    pub event_index: u32,
    pub destination_address: String,
    pub destination_chain: router_api::ChainName,
    pub source_address: XRPLAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: XRPLAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

pub struct Handler<C>
where
    C: XRPLClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: XRPLClient,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            rpc_client,
            latest_block_height,
        }
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier_contract.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            messages,
            expires_at,
            confirmation_height,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if source_chain != ChainName::from_str(XRPL_CHAIN_NAME).unwrap() { // TODO: remove unwrap
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        // TODO: move logic to finalized_tx_receipts() to match evm_verify_msg
        // Copied from EVM verifier:
        /*let tx_hashes: HashSet<_> = messages.iter().map(|message| message.tx_id).collect();
        let finalized_tx_receipts = self
            .finalized_tx_receipts(tx_hashes, confirmation_height)
            .await?;
        */

        // Does not assume voting verifier emits unique tx ids.
        // RPC will throw an error if the input contains any duplicate, deduplicate tx ids to avoid unnecessary failures.
        let deduplicated_tx_ids: HashSet<_> = messages.iter().map(|msg| msg.tx_id.clone()).collect();

        let mut tx_responses = HashMap::new();

        for tx_id in deduplicated_tx_ids {
            match self.rpc_client.fetch_tx(tx_id).await {
                Ok(res) => { tx_responses.insert(tx_id, res); },
                Err(e) => return Err(e.change_context(Error::TxReceipts))
            }
        }

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();
        let message_ids = messages
            .iter()
            .map(|message| {
                HexTxHashAndEventIndex::new(message.tx_id, message.event_index).to_string()
            })
            .collect::<Vec<_>>();

        let votes = info_span!(
            "verify messages from XRPL chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = message_ids.as_value()
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    tx_responses // TODO: should be finalized_tx_receipts
                        .get(&msg.tx_id)
                        .and_then(|tx_response| tx_response.as_ref().map(|tx| {
                            verify_message(&source_gateway_address, &tx.tx, msg) // TODO: clean up
                        }))
                        .unwrap_or(Vote::NotFound)
                })
                .collect();
            info!(
                votes = votes.as_value(),
                "ready to vote for messages in poll"
            );

            votes
        });

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }
}