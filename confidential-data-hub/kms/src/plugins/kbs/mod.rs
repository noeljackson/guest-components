// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Abstraction for KBCs as a KMS plugin.

#[cfg(feature = "kbs")]
mod cc_kbc;

mod offline_fs;

use std::{env, sync::Arc};

#[cfg(any(feature = "kbs", test))]
use std::{num::NonZeroU32, time::Duration};

use async_trait::async_trait;
use attestation_agent::config::aa_kbc_params::AaKbcParams;
pub use resource_uri::ResourceUri;
use tokio::sync::Mutex;

use crate::{Annotations, Error, Getter, Result};

pub const AA_TOKEN_REQUEST_TIMEOUT_SECS_ENV: &str = "AA_TOKEN_REQUEST_TIMEOUT_SECS";
#[cfg(any(feature = "kbs", test))]
const DEFAULT_AA_TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(50);

#[async_trait]
pub trait Kbc: Send + Sync {
    async fn get_resource(&mut self, _rid: ResourceUri) -> Result<Vec<u8>>;
}

/// A fake KbcClient to carry the [`Getter`] semantics. The real `new()`
/// and `get_resource()` will happen to the static variable [`KBS_CLIENT`].
pub enum KbcClient {
    #[cfg(feature = "kbs")]
    Cc(Arc<Mutex<cc_kbc::CcKbc>>),
    OfflineFs(Arc<Mutex<offline_fs::OfflineFsKbc>>),
}

impl KbcClient {
    pub async fn new() -> Result<Self> {
        let params = env::var("AA_KBC_PARAMS").expect("must be initialized");
        let params = AaKbcParams::try_from(params)
            .map_err(|e| Error::KbsClientError(format!("Failed to parse aa_kbc_params: {e:?}")))?;

        let c = match &params.kbc[..] {
            #[cfg(feature = "kbs")]
            "cc_kbc" => {
                let request_timeout = aa_token_request_timeout(
                    env::var(AA_TOKEN_REQUEST_TIMEOUT_SECS_ENV).ok().as_deref(),
                )?;
                let aa_socket = env::var("AA_SOCKET").expect("must be initialized");
                Self::Cc(Arc::new(Mutex::new(
                    cc_kbc::CcKbc::new_with_timeout(&params.uri, &aa_socket, request_timeout)
                        .await?,
                )))
            }
            "offline_fs_kbc" => {
                Self::OfflineFs(Arc::new(Mutex::new(offline_fs::OfflineFsKbc::new().await?)))
            }
            others => {
                return Err(Error::KbsClientError(format!(
                    "unknown kbc name {others}, only support `cc_kbc`(feature `kbs`) and `offline_fs_kbc`."
                )));
            }
        };

        Ok(c)
    }
}

#[cfg(any(feature = "kbs", test))]
fn aa_token_request_timeout(raw: Option<&str>) -> Result<Duration> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_AA_TOKEN_REQUEST_TIMEOUT);
    };
    let seconds = raw.parse::<NonZeroU32>().map_err(|e| {
        Error::KbsClientError(format!("invalid {AA_TOKEN_REQUEST_TIMEOUT_SECS_ENV}: {e}"))
    })?;
    Ok(Duration::from_secs(u64::from(seconds.get())))
}

#[async_trait]
impl Getter for KbcClient {
    async fn get_secret(&self, name: &str, _annotations: &Annotations) -> Result<Vec<u8>> {
        let resource_uri = ResourceUri::try_from(name)
            .map_err(|_| Error::KbsClientError(format!("illegal kbs resource uri: {name}")))?;

        match self {
            #[cfg(feature = "kbs")]
            Self::Cc(c) => c.lock().await.get_resource(resource_uri).await,
            Self::OfflineFs(c) => c.lock().await.get_resource(resource_uri).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_request_timeout_defaults_to_fifty_seconds() {
        assert_eq!(
            aa_token_request_timeout(None).unwrap(),
            Duration::from_secs(50)
        );
    }

    #[test]
    fn token_request_timeout_accepts_trusted_override() {
        assert_eq!(
            aa_token_request_timeout(Some("300")).unwrap(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn token_request_timeout_rejects_zero_and_malformed_values() {
        assert!(aa_token_request_timeout(Some("0")).is_err());
        assert!(aa_token_request_timeout(Some("invalid")).is_err());
    }
}
