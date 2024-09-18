use std::collections::HashMap;

use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use router_api::{Address, ChainName};

use crate::contract::Contract;

#[derive(Clone)]
pub struct InterchainTokenServiceContract {
    pub contract_addr: Addr,
}

impl InterchainTokenServiceContract {
    pub fn instantiate_contract(
        app: &mut App,
        axelarnet_gateway: Addr,
        governance: Addr,
        admin: Addr,
        its_addresses: HashMap<ChainName, Address>,
    ) -> Self {
        let code = ContractWrapper::new(
            interchain_token_service::contract::execute,
            interchain_token_service::contract::instantiate,
            interchain_token_service::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &interchain_token_service::msg::InstantiateMsg {
                    axelarnet_gateway_address: axelarnet_gateway.to_string(),
                    governance_address: governance.to_string(),
                    admin_address: admin.to_string(),
                    its_addresses,
                },
                &[],
                "interchain_token_service",
                None,
            )
            .unwrap();

        InterchainTokenServiceContract { contract_addr }
    }
}

impl Contract for InterchainTokenServiceContract {
    type QMsg = interchain_token_service::msg::QueryMsg;
    type ExMsg = interchain_token_service::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
