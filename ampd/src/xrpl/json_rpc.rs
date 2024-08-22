use async_trait::async_trait;
use mockall::automock;
use xrpl_http_client::{TxRequest, TxResponse, Client, error};

use crate::types::Hash; // TODO: use XRPL hash type instead of ethers?

type Result<T> = error_stack::Result<T, error::Error>;

#[automock]
#[async_trait]
pub trait XRPLClient {
    async fn fetch_tx(
        &self,
        tx_id: Hash,
    ) -> Result<Option<TxResponse>>;
}

#[async_trait]
impl XRPLClient for Client {
    async fn fetch_tx(&self, tx_id: Hash) -> Result<Option<TxResponse>> {
        let req = TxRequest::new(tx_id.to_string().as_str());
        self.call(req).await.map(Some).or_else(|err| match err {
            error::Error::Api(reason) if reason == "txnNotFound" => Ok(None),
            _ => Err(err.into()),
        })
    }
}
