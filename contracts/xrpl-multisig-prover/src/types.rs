
pub fn canonicalize_coin_amount(
    amount: Uint128,
    decimals: u8,
) -> Result<XRPLTokenAmount, ContractError> {
    let (mantissa, exponent) = canonicalize_mantissa(amount, -i64::from(decimals))?;
    Ok(XRPLTokenAmount::new(mantissa, exponent))
}

// always called when XRPLTokenAmount instantiated
// see https://github.com/XRPLF/xrpl-dev-portal/blob/82da0e53a8d6cdf2b94a80594541d868b4d03b94/content/_code-samples/tx-serialization/py/xrpl_num.py#L19
pub fn canonicalize_mantissa(
    mut mantissa: Uint128,
    mut exponent: i64,
) -> Result<(u64, i64), ContractError> {
    let ten = Uint128::from(10u128);

    while mantissa < MIN_MANTISSA.into() && exponent > MIN_EXPONENT {
        mantissa *= ten;
        exponent -= 1;
    }

    while mantissa > MAX_MANTISSA.into() && exponent > MIN_EXPONENT {
        if exponent > MAX_EXPONENT {
            return Err(ContractError::InvalidAmount {
                reason: "overflow".to_string(),
            });
        }
        mantissa /= ten;
        exponent += 1;
    }

    if exponent < MIN_EXPONENT || mantissa < MIN_MANTISSA.into() {
        return Ok((0, 1));
    }

    if exponent > MAX_EXPONENT || mantissa > MAX_MANTISSA.into() {
        return Err(ContractError::InvalidAmount {
            reason: format!("overflow exponent {} mantissa {}", exponent, mantissa).to_string(),
        });
    }

    let mantissa = u64::from_be_bytes(mantissa.to_be_bytes()[8..].try_into().unwrap());

    Ok((mantissa, exponent))
}