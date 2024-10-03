use std::collections::HashMap;
use std::str::FromStr;

use xrpl_http_client::{Amount, ResultCategory};
use xrpl_http_client::{Memo, Transaction::Payment, Transaction};
use axelar_wasm_std::voting::Vote;
use xrpl_types::msg::{UserMessage, XRPLMessage};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken};

use crate::xrpl::types::XRPLAddress;

pub fn verify_message(
    multisig_address: &XRPLAddress,
    tx: &Transaction,
    message: &XRPLMessage,
) -> Vote {
    if is_validated_tx(tx) && (is_valid_multisig_tx(tx, multisig_address, message) || is_valid_deposit_tx(tx, multisig_address, message)) {
        if is_successful_tx(tx) {
            Vote::SucceededOnChain
        } else {
            Vote::FailedOnChain
        }
    } else {
        Vote::NotFound
    }
}

pub fn is_validated_tx(tx: &Transaction) -> bool {
    matches!(tx.common().validated, Some(true))
}

pub fn is_valid_multisig_tx(tx: &Transaction, multisig_address: &XRPLAddress, message: &XRPLMessage) -> bool {
    tx.common().account == multisig_address.0 && matches!(message, XRPLMessage::ProverMessage(_))
}

pub fn is_valid_deposit_tx(tx: &Transaction, multisig_address: &XRPLAddress, message: &XRPLMessage) -> bool {
    if let Payment(payment_tx) = &tx {
        if let Some(memos) = payment_tx.clone().common.memos {
            if let XRPLMessage::UserMessage(user_msg) = message {
                return payment_tx.destination == multisig_address.0 && user_msg.source_address.to_string() == tx.common().account && verify_memos(payment_tx.amount.clone(), memos, user_msg);
            }
        }
    }
    return false;
}

pub fn is_successful_tx(tx: &Transaction) -> bool {
    if let Some(meta) = &tx.common().meta {
        return meta.transaction_result.category() == ResultCategory::Tes;
    }
    return false;
}

fn remove_0x_prefix(s: String) -> String {
    if s.starts_with("0x") {
        s[2..].to_string()
    } else {
        s
    }
}

pub fn verify_memos(amount: Amount, memos: Vec<Memo>, message: &UserMessage) -> bool {
    let memo_kv: HashMap<String, String> = memos
        .into_iter()
        .filter(|m| m.memo_type.is_some() && m.memo_data.is_some())
        .map(|m| (String::from_utf8(hex::decode(m.memo_type.unwrap()).unwrap()).unwrap(), m.memo_data.unwrap()))
        .collect();

    || -> Option<bool> {
        let amount = match amount {
            Amount::Issued(a) => XRPLPaymentAmount::Token(
                XRPLToken {
                    issuer: XRPLAccountId::from_str(&a.issuer).unwrap(),
                    currency: XRPLCurrency::try_from(a.currency).unwrap(),
                },
                a.value.try_into().ok()?
            ),
            Amount::Drops(a) => XRPLPaymentAmount::Drops(a.parse().ok()?),
        };

        Some(
            memo_kv.get("destination_address")? == &remove_0x_prefix(message.destination_address.to_string()).to_uppercase()
            && memo_kv.get("destination_chain")? == &hex::encode_upper(message.destination_chain.to_string())
            && hex::decode(&remove_0x_prefix(memo_kv.get("payload_hash")?.clone())).ok()? == message.payload_hash
            && amount == message.amount
        )
    }().unwrap_or(false)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::xrpl::verifier::verify_memos;
    use cosmwasm_std::HexBinary;
    use xrpl_http_client::{Amount, Memo};
    use xrpl_types::{msg::UserMessage, types::{XRPLAccountId, XRPLPaymentAmount}};
    use router_api::{Address, ChainName};

    // TODO: add adapted EVM tests

    #[test]
    fn test_verify_memos() {
        let memos = vec![
            Memo {
                memo_type: Some("64657374696E6174696F6E5F61646472657373".to_string()),
                memo_data: Some("592639C10223C4EC6C0FFC670E94D289A25DD1AD".to_string()),
                memo_format: None
            },
            Memo {
                memo_type: Some("64657374696E6174696F6E5F636861696E".to_string()),
                memo_data: Some("657468657265756D".to_string()),
                memo_format: None
            },
            Memo {
                memo_type: Some("7061796C6F61645F68617368".to_string()),
                memo_data: Some("4F246000525114CC0CC261973D12E9A1C53B7AA295DF41FA6A6BFD00045BF0E6".to_string()),
                memo_format: None
            }
        ];
        let user_message = UserMessage {
            tx_id: [0; 32],
            source_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo").unwrap(),
            destination_address: HexBinary::from_hex("592639c10223C4EC6C0ffc670e94d289A25DD1ad").unwrap(),
            destination_chain: ChainName::from_str("ethereum").unwrap(),
            payload_hash: hex::decode("feb30b51f41e4785664824dd0ee694e0d275757753f570e9f6b5e27d06197fa7").unwrap().to_vec().try_into().unwrap(),
            amount: XRPLPaymentAmount::Drops(100000),
        };
        assert!(verify_memos(Amount::Drops("1000000".to_string()), memos, &user_message));
    }
}
