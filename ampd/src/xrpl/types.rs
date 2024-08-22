use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq)]
pub struct XRPLAddress(pub String);