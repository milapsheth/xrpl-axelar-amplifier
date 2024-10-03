use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use xrpl_types::{msg::{XRPLMessage, XRPLMessageWithPayload}, types::XRPLTokenOrXRP};
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
    /// Chain name of the XRPL chain.
    pub xrpl_chain_name: ChainName,
}

#[cw_serde]
pub struct InterchainTokenDeployment {
    pub xrpl_token: XRPLTokenOrXRP,
    pub destination_chain: ChainName,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub minter: HexBinary,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// TODO
    #[permission(Any)] // TODO: make permissioned
    DeployXRPToSidechain { sidechain_name: ChainName, params: HexBinary },

    /// TODO
    #[permission(Any)] // TODO: make permissioned
    DeployInterchainToken(InterchainTokenDeployment),

    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    #[permission(Any)]
    VerifyMessages(Vec<XRPLMessage>),

    /// Forward the given messages to the next step of the routing layer.
    /// NOTE: In our (XRPL) case, outgoing messages only, therefore they are already verified.
    /// NOTE: Should be named RouteOutgoingMessages, but we keep the name for compatibility with the router.
    #[permission(Any)]
    RouteMessages(Vec<Message>),


    /// Forward the given messages to the next step of the routing layer.
    /// They are reported by the relayer and need verification.
    #[permission(Any)]
    RouteIncomingMessages(Vec<XRPLMessageWithPayload>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    OutgoingMessages(Vec<CrossChainId>),
}
