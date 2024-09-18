use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use router_api::ChainName;

use crate::contract::Contract;

#[derive(Clone)]
pub struct AxelarnetGatewayContract {
    pub contract_addr: Addr,
}

impl AxelarnetGatewayContract {
    pub fn instantiate_contract(
        app: &mut App,
        chain_name: ChainName,
        router_address: Addr,
    ) -> Self {
        let code = ContractWrapper::new(
            axelarnet_gateway::contract::execute,
            axelarnet_gateway::contract::instantiate,
            axelarnet_gateway::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &axelarnet_gateway::msg::InstantiateMsg {
                    chain_name,
                    router_address: router_address.to_string(),
                },
                &[],
                "axelarnet_gateway",
                None,
            )
            .unwrap();

        AxelarnetGatewayContract { contract_addr }
    }
}

impl Contract for AxelarnetGatewayContract {
    type QMsg = axelarnet_gateway::msg::QueryMsg;
    type ExMsg = axelarnet_gateway::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
