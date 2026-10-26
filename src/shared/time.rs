use std::future::Future;
use std::time::Duration;

use tokio::time;

use crate::shared::error::Error;
use crate::shared::node::Node;

/// Run `operation` with `node`, failing with [`Error::Timeout`] if it takes longer than
/// `limit`.
pub(crate) async fn within<T>(
    limit: Duration,
    operation: &'static str,
    node: &Node,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    match time::timeout(limit, future).await {
        Ok(result) => result,
        Err(_) => Err(Error::Timeout {
            operation,
            node: node.clone(),
            after: limit,
        }),
    }
}
