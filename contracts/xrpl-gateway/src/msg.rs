use cosmwasm_schema::{cw_serde, QueryResponses};
use xrpl_types::msg::XRPLMessage;
use router_api::{ChainName, CrossChainId, Message};
use msgs_derive::EnsurePermissions;

#[cw_serde]
pub struct InstantiateMsg {
    /// Address of the verifier contract on axelar associated with the source chain. E.g., the voting verifier contract.
    pub verifier_address: String,
    /// Address of the router contract on axelar.
    pub router_address: String,
    /// Address of the ITS Hub contract on axelar.
    pub its_hub_address: String,
    /// Chain name of the axelar chain.
    pub axelar_chain_name: ChainName,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    #[permission(Any)]
    VerifyMessages(Vec<XRPLMessage>),

    /// Forward the given messages to the next step of the routing layer.
    /// NOTE: In our (XRPL) case, outgoing messages only, therefore they are already verified.
    #[permission(Any)]
    RouteOutgoingMessages(Vec<Message>),


    /// Forward the given messages to the next step of the routing layer.
    /// They are reported by the relayer and need verification.
    #[permission(Any)]
    RouteIncomingMessages(Vec<XRPLMessage>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    OutgoingMessages(Vec<CrossChainId>),
}
