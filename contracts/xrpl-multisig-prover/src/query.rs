use cosmwasm_std::{StdResult, Uint64, HexBinary, Storage};

use multisig::types::MultisigState;

// TODO: remove dependency?
use k256::{ecdsa, schnorr::signature::SignatureEncoding};

use crate::{
    state::{MULTISIG_SESSION_TX, TRANSACTION_INFO}, xrpl_multisig::{XRPLUnsignedTx, XRPLSignedTransaction, XRPLSigner, self, XRPLSerialize}, querier::Querier, contract::{GetProofResponse, GetMessageToSignResponse}, types::TransactionStatus, error::ContractError,
};

pub fn make_xrpl_signed_tx(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> Result<XRPLSignedTransaction, ContractError> {
    let xrpl_signers: Vec<XRPLSigner> = axelar_signers
        .iter()
        .map(|(axelar_signer, signature)| {
            let xrpl_address = xrpl_multisig::public_key_to_xrpl_address(axelar_signer.pub_key.clone());
            XRPLSigner {
                account: xrpl_address,
                signing_pub_key: axelar_signer.pub_key.clone().into(),
                // TODO: should work with Ed25519 signatures too
                txn_signature: HexBinary::from(ecdsa::Signature::to_der(
                    &ecdsa::Signature::try_from(signature.clone().as_ref())
                        .map_err(|_| ContractError::FailedToEncodeSignature).unwrap() // TODO: FIX - SHOULD NOT UNWRAP
                ).to_vec()),
            }
        })
        .collect::<Vec<XRPLSigner>>();

    Ok(XRPLSignedTransaction {
        unsigned_tx,
        signers: xrpl_signers,
    })
}

pub fn get_message_to_sign(storage: &dyn Storage, multisig_session_id: &Uint64, signer_xrpl_address: &String) -> StdResult<GetMessageToSignResponse> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusNotPending.into());
    }

    let serialized_unsigned_tx = tx_info.unsigned_contents.xrpl_serialize()?;
    let serialized_signer_xrpl_address = xrpl_multisig::decode_address(signer_xrpl_address)?;

    let serialized_tx = &[serialized_unsigned_tx, serialized_signer_xrpl_address.to_vec()].concat();

    Ok(GetMessageToSignResponse {
        tx_hash: xrpl_multisig::xrpl_hash(None, serialized_tx).into()
    })
}

pub fn get_proof(storage: &dyn Storage, querier: Querier, multisig_session_id: &Uint64) -> StdResult<GetProofResponse> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;

    let multisig_session= querier.get_multisig_session(multisig_session_id.clone())?;

    let response = match multisig_session.state {
        MultisigState::Pending => GetProofResponse::Pending { unsigned_tx_hash },
        MultisigState::Completed { .. } => {
            let axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)> = multisig_session.signers
                .iter()
                .filter(|(_, signature)| signature.is_some())
                .map(|(signer, signature)| (signer.clone(), signature.clone().unwrap()))
                .collect();

            let signed_tx = make_xrpl_signed_tx(tx_info.unsigned_contents, axelar_signers)?;
            let tx_blob: HexBinary = HexBinary::from(signed_tx.xrpl_serialize()?);
            GetProofResponse::Completed { unsigned_tx_hash, tx_blob }
        }
    };

    Ok(response)
}
