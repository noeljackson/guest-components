// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::client::ttrpc_client::CachedTtrpcClient;
use anyhow::*;
use protos::ttrpc::cdh::api::GetResourceRequest;
use protos::ttrpc::cdh::api_ttrpc::GetResourceServiceClient;
use std::time::Duration;

/// ROOT path for Confidential Data Hub API
pub const CDH_ROOT: &str = "/cdh";

/// URL for querying CDH get resource API
pub const CDH_RESOURCE_URL: &str = "/resource";

const KBS_PREFIX: &str = "kbs://";

pub struct CDHClient {
    client: CachedTtrpcClient<GetResourceServiceClient>,
    request_timeout: Duration,
}

impl CDHClient {
    pub async fn new(cdh_addr: &str, request_timeout: Duration) -> Result<Self> {
        let client = CachedTtrpcClient::new(cdh_addr, "CDH", GetResourceServiceClient::new).await?;

        Ok(Self {
            client,
            request_timeout,
        })
    }

    pub async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let resource_path = format!("{KBS_PREFIX}{resource_path}");

        let res = self
            .client
            .call_with_retry(|client| {
                let resource_path = resource_path.clone();

                async move {
                    let req = GetResourceRequest {
                        ResourcePath: resource_path,
                        ..Default::default()
                    };

                    client
                        .get_public_resource(request_context(self.request_timeout), &req)
                        .await
                }
            })
            .await?;

        Ok(res.Resource)
    }
}

fn request_context(timeout: Duration) -> ttrpc::context::Context {
    ttrpc::context::with_duration(timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_context_uses_selected_timeout() {
        assert_eq!(
            request_context(Duration::from_secs(300)).timeout_nano,
            300_000_000_000
        );
    }
}
