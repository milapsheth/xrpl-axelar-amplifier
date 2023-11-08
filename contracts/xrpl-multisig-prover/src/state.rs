use axelar_wasm_std::Threshold;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct Config {
    pub axelar_multisig_address: Addr,
    pub gateway_address: Addr,
    pub signing_threshold: Threshold,
    pub xrpl_multisig_address: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");
