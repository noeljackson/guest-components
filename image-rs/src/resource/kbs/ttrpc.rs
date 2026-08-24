// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Resource ttrpc client

use anyhow::*;
use async_trait::async_trait;
use protos::ttrpc::cdh::{api::GetResourceRequest, api_ttrpc::GetResourceServiceClient};
use std::time::Duration;
use tokio::sync::OnceCell;
use ttrpc::context;

use super::Client;

const SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

pub struct Ttrpc {
    client: OnceCell<GetResourceServiceClient>,
    timeout: Duration,
}

impl Default for Ttrpc {
    fn default() -> Self {
        Self::new(crate::config::ImageConfig::default().resource_provider_timeout())
    }
}

impl Ttrpc {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            client: OnceCell::new(),
            timeout,
        }
    }

    fn request_context(&self) -> context::Context {
        context::with_duration(self.timeout)
    }
}

#[async_trait]
impl Client for Ttrpc {
    async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            ResourcePath: resource_path.to_string(),
            ..Default::default()
        };

        let res = self
            .client
            .get_or_try_init(|| async {
                let inner = ttrpc::asynchronous::Client::connect(SOCKET_ADDR).await?;
                Ok(GetResourceServiceClient::new(inner))
            })
            .await?
            .get_resource(self.request_context(), &req)
            .await
            .context("ttrpc request error")?;
        Ok(res.Resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_context_uses_configured_timeout() {
        let timeout = Duration::from_secs(300);
        let client = Ttrpc::new(timeout);

        assert_eq!(client.request_context().timeout_nano, 300_000_000_000);
    }

    #[test]
    fn request_context_preserves_default_timeout() {
        assert_eq!(
            Ttrpc::default().request_context().timeout_nano,
            50_000_000_000
        );
    }
}
