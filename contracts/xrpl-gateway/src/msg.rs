use connection_router::state::Message;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub enum ExecuteMsg {
    // Permissionless
    VerifyMessages(Vec<Message>),

    // Permissionless
    RouteMessages(Vec<Message>),
}
