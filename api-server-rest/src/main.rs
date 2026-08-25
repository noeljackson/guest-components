// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;
use hyper::Server;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use shadow_rs::shadow;
use std::fs;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt::Subscriber};

shadow!(build);

mod client;
mod router;
mod utils;

use router::Router;

use crate::client::aa::AAClient;
use crate::client::cdh::CDHClient;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

pub const AA_TTRPC_TIMEOUT: i64 = 50 * 1000 * 1000 * 1000;
const DEFAULT_CDH_TTRPC_TIMEOUT_SECS: u64 = 50;
const IMAGE_RESOURCE_TIMEOUT_PARAM: &str = "agent.image_resource_timeout_secs";
const DEFAULT_BIND: &str = "127.0.0.1:8006";
const DEFAULT_FEATURE: &str = "resource";
const CDH_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
const AA_ADDR: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/guest_components_version"));

/// API Server arguments info.
#[derive(Parser, Debug)]
#[command(author, version = Some(VERSION), about, long_about = None)]
struct Args {
    /// Bind address for API Server
    #[arg(default_value_t = DEFAULT_BIND.to_string(), short, long = "bind")]
    bind: String,

    /// Features for rest API Server, allowed options: resource, attestation, all
    #[arg(default_value_t = DEFAULT_FEATURE.to_string(), short, long = "features")]
    features: String,

    /// Listen address of confidential-data-hub TTRPC Service
    #[arg(default_value_t = CDH_ADDR.to_string(), short, long = "cdh_addr")]
    cdh_addr: String,

    /// Listen address of attestation-agent TTRPC Service
    #[arg(default_value_t = AA_ADDR.to_string(), short, long = "aa_addr")]
    aa_addr: String,

    /// CDH resource request timeout in seconds. If omitted, use the validated
    /// image resource timeout from the kernel command line, then 50 seconds.
    #[arg(long = "cdh_timeout_secs")]
    cdh_timeout_secs: Option<NonZeroU32>,
}

fn kernel_image_resource_timeout(cmdline: &str) -> Option<NonZeroU32> {
    cmdline
        .split_ascii_whitespace()
        .filter_map(|item| item.split_once('='))
        .filter(|(key, _)| *key == IMAGE_RESOURCE_TIMEOUT_PARAM)
        .map(|(_, value)| value)
        .next_back()
        .and_then(|value| value.parse::<NonZeroU32>().ok())
}

fn select_cdh_request_timeout(
    cli_timeout: Option<NonZeroU32>,
    cmdline: Option<&str>,
) -> (Duration, &'static str) {
    if let Some(timeout) = cli_timeout {
        return (Duration::from_secs(timeout.get().into()), "cli");
    }

    if let Some(timeout) = cmdline.and_then(kernel_image_resource_timeout) {
        return (Duration::from_secs(timeout.get().into()), "kernel");
    }

    (
        Duration::from_secs(DEFAULT_CDH_TTRPC_TIMEOUT_SECS),
        "default",
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("info"),
    };

    Subscriber::builder().with_env_filter(env_filter).init();

    let args = Args::parse();
    let kernel_cmdline = fs::read_to_string("/proc/cmdline").ok();
    let (cdh_request_timeout, cdh_timeout_source) =
        select_cdh_request_timeout(args.cdh_timeout_secs, kernel_cmdline.as_deref());

    info!(
        "Starting API server on {} with features {}",
        args.bind, args.features
    );
    info!(
        "CDH ttrpc request timeout is {} seconds (source: {})",
        cdh_request_timeout.as_secs(),
        cdh_timeout_source
    );

    let address: SocketAddr = args.bind.parse().expect("Failed to parse the address");

    let (aa_client, cdh_client) = match args.features.as_str() {
        "resource" => (
            None,
            Some(CDHClient::new(&args.cdh_addr, cdh_request_timeout).await?),
        ),
        "attestation" => (Some(AAClient::new(&args.aa_addr).await?), None),
        "all" => (
            Some(AAClient::new(&args.aa_addr).await?),
            Some(CDHClient::new(&args.cdh_addr, cdh_request_timeout).await?),
        ),
        _ => {
            error!("Unknown features. Supported features are: resource, attestation, all.");
            std::process::exit(1);
        }
    };
    let router = Router::new(aa_client, cdh_client, args.features);

    let router = Arc::new(router);

    let api_service = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let local_router = router.clone();

        async move {
            Ok::<_, GenericError>(service_fn(move |req| {
                let local_router = local_router.clone();
                async move { local_router.route(remote_addr, req).await }
            }))
        }
    });

    let server = Server::bind(&address).serve(api_service);

    info!("API Server listening on http://{}", args.bind);

    if let Err(e) = server.await {
        error!("API server error: {e}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdh_timeout_uses_kernel_image_resource_contract() {
        let (timeout, source) = select_cdh_request_timeout(
            None,
            Some("quiet agent.image_resource_timeout_secs=300 console=ttyS0"),
        );

        assert_eq!(timeout, Duration::from_secs(300));
        assert_eq!(source, "kernel");
    }

    #[test]
    fn cdh_timeout_preserves_default_for_missing_or_invalid_kernel_value() {
        for cmdline in [
            None,
            Some("quiet"),
            Some("agent.image_resource_timeout_secs=0"),
            Some("agent.image_resource_timeout_secs=invalid"),
        ] {
            assert_eq!(
                select_cdh_request_timeout(None, cmdline),
                (
                    Duration::from_secs(DEFAULT_CDH_TTRPC_TIMEOUT_SECS),
                    "default"
                )
            );
        }
    }

    #[test]
    fn cdh_timeout_uses_last_kernel_value_like_image_config() {
        let (timeout, source) = select_cdh_request_timeout(
            None,
            Some("agent.image_resource_timeout_secs=50 agent.image_resource_timeout_secs=300"),
        );

        assert_eq!(timeout, Duration::from_secs(300));
        assert_eq!(source, "kernel");
    }

    #[test]
    fn explicit_cdh_timeout_overrides_kernel_value() {
        let explicit = NonZeroU32::new(120).unwrap();
        let (timeout, source) = select_cdh_request_timeout(
            Some(explicit),
            Some("agent.image_resource_timeout_secs=300"),
        );

        assert_eq!(timeout, Duration::from_secs(120));
        assert_eq!(source, "cli");
    }

    #[test]
    fn cdh_timeout_cli_accepts_only_nonzero_seconds() {
        let args = Args::try_parse_from(["api-server-rest", "--cdh_timeout_secs", "120"])
            .expect("nonzero timeout should parse");
        assert_eq!(args.cdh_timeout_secs, NonZeroU32::new(120));

        assert!(Args::try_parse_from(["api-server-rest", "--cdh_timeout_secs", "0"]).is_err());
    }
}
