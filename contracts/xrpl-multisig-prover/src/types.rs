use cosmwasm_std::Uint128;

use xrpl_types::types::*;

use crate::error::ContractError;

pub fn canonicalize_coin_amount(
    amount: Uint128,
    decimals: u8,
) -> Result<XRPLTokenAmount, ContractError> {
    let (mantissa, exponent) = canonicalize_mantissa(amount, -i64::from(decimals))?;
    Ok(XRPLTokenAmount::new(mantissa, exponent))
}
