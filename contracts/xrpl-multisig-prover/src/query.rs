use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{to_binary, Deps, QueryRequest, StdResult, Uint64, WasmQuery, HexBinary};

use multisig::{msg::Multisig, types::MultisigState};

use crate::{
    state::{CONFIG, MULTISIG_SESSION_TX, TRANSACTION_INFO}, types::TxHash, xrpl_multisig::{XRPLUnsignedTx, XRPLSignedTransaction, XRPLSigner, self},
};

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },
}

#[cw_serde]
#[serde(tag = "status")]
pub enum GetProofResponse {
    Completed { tx_hash: TxHash, tx_blob: HexBinary},
    Pending { tx_hash: TxHash },
}

pub fn make_xrpl_signed_tx(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> XRPLSignedTransaction {
    let xrpl_signers: Vec<XRPLSigner> = axelar_signers
        .iter()
        .map(|(axelar_signer, signature)| {
            let xrpl_address = xrpl_multisig::public_key_to_xrpl_address(axelar_signer.pub_key.clone());
            XRPLSigner {
                account: xrpl_address,
                signing_pub_key: axelar_signer.pub_key.clone().into(),
                txn_signature: HexBinary::from(signature.clone().as_ref())
            }
        })
        .collect::<Vec<XRPLSigner>>();

    XRPLSignedTransaction {
        unsigned_tx,
        signers: xrpl_signers,
    }
}

pub fn get_proof(deps: Deps, multisig_session_id: Uint64) -> StdResult<GetProofResponse> {
    let config = CONFIG.load(deps.storage)?;

    let tx_hash = MULTISIG_SESSION_TX.load(deps.storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(deps.storage, tx_hash.clone())?;

    let query_msg = multisig::msg::QueryMsg::GetMultisig {
        session_id: multisig_session_id,
    };

    let multisig_session: Multisig = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.axelar_multisig_address.to_string(),
        msg: to_binary(&query_msg)?,
    }))?;

    let response = match multisig_session.state {
        MultisigState::Pending => GetProofResponse::Pending { tx_hash },
        MultisigState::Completed { .. } => {
            let axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)> = multisig_session.signers
                .iter()
                .filter(|(_, signature)| signature.is_some())
                .map(|(signer, signature)| (signer.clone(), signature.clone().unwrap()))
                .collect();

            let signed_tx = make_xrpl_signed_tx(tx_info.unsigned_contents, axelar_signers);
            // TODO: serialize using XRPL encoding: https://xrpl.org/serialization.html
            let tx_blob: HexBinary = signed_tx.try_into()?;
            GetProofResponse::Completed { tx_hash, tx_blob }
        }
    };

    Ok(response)
}
