// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::debug;

use crate::registry::Config as RegistryConfig;
use crate::snapshots::SnapshotType;

/// By default use a work dir in `/run` because for confidential guests `/run`
/// is typically in a `tmpfs` which is backed by encrypted memory.
pub const DEFAULT_WORK_DIR: &str = "/run/kata-containers/image/";

/// Default path to policy file in KBS or locally
pub const POLICY_FILE_PATH: &str = "kbs:///default/security-policy/test";

/// Default path to sig store config in KBS or locally
pub const SIG_STORE_CONFIG_DEFAULT_FILE: &str = "kbs:///default/sigstore-config/test";

/// Default path to auth.json in KBS or locally
pub const AUTH_FILE_PATH: &str = "kbs:///default/credential/test";

/// Default max concurrent downloads
pub const DEFAULT_MAX_CONCURRENT_DOWNLOAD: usize = 3;

/// Default timeout for retrieving one resource from the configured provider.
pub const DEFAULT_RESOURCE_PROVIDER_TIMEOUT_SECS: u32 = 50;

/// Path to the configuration file to generate ImageConfiguration
pub const CONFIGURATION_FILE_NAME: &str = "config.json";

/// One registry host and the address a pull reaches it at.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RegistryAddress {
    /// The registry's host name as the pull resolves it, with no port, matched
    /// without regard to case. For Docker Hub that is `index.docker.io`, not
    /// `docker.io`.
    pub host: String,
    /// The address to connect to. The port stays the reference's.
    pub address: IpAddr,
}

/// Refuses an empty host, a host that is itself an address or carries a port
/// or path, and a host listed twice. Also refuses any fixed address alongside
/// an HTTPS pull proxy: the proxy resolves the host itself, so the address
/// would go unused without a word.
pub fn validate_registry_addresses(
    addresses: &[RegistryAddress],
    image_pull_proxy: Option<&ProxyConfig>,
) -> Result<()> {
    if !addresses.is_empty() && image_pull_proxy.is_some_and(|proxy| proxy.https_proxy.is_some()) {
        return Err(anyhow!(
            "registry addresses can't be used with an https image pull proxy"
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for entry in addresses {
        let host = entry.host.as_str();
        if host.is_empty() || host.contains([':', '/', '@']) || host.parse::<IpAddr>().is_ok() {
            return Err(anyhow!(
                "registry address host {host:?} must be a host name without port or path"
            ));
        }
        if !seen.insert(host.to_ascii_lowercase()) {
            return Err(anyhow!("registry address host {host:?} is listed twice"));
        }
    }
    Ok(())
}

/// The address for a reference's registry (`host` or `host:port`), when one
/// is listed for exactly that host.
pub fn registry_address_for<'a>(
    addresses: &'a [RegistryAddress],
    registry: &str,
) -> Option<&'a RegistryAddress> {
    let host = match registry.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => registry,
    };
    addresses
        .iter()
        .find(|entry| entry.host.eq_ignore_ascii_case(host))
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ProxyConfig {
    /// HTTPS proxy that will be used to pull image
    ///
    /// If a registry is not accessible to the guest, you can try
    /// pulling an image through a proxy specified here.
    ///
    /// This value defaults to `None`.
    #[serde(default)]
    pub https_proxy: Option<String>,

    /// HTTP proxy that will be used to pull image
    ///
    /// If a registry is not accessible to the guest, you can try
    /// pulling an image through a proxy specified here.
    ///
    /// This value defaults to `None`.
    #[serde(default)]
    pub http_proxy: Option<String>,

    /// If the above proxy is enabled, this field can be used to list IPs
    /// that will bypass the proxy.
    ///
    /// In other words all requests, except those made to these IPs,
    /// will go through the proxy.
    ///
    /// If `image_pull_proxy` is not set, this field will do nothing.
    ///
    /// This value defaults to `None`.
    #[serde(default)]
    pub no_proxy: Option<String>,
}

/// `image-rs` configuration information.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ImageConfig {
    /// The location for `image-rs` to store data.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    #[serde(skip)]
    pub default_snapshot: SnapshotType,

    /// An image security policy regulates which images can be pulled by image-rs
    /// and if/how images are validated when they are pulled.
    /// For example, a policy can require that images from a particular registry
    /// are signed with a particular scheme.
    ///
    /// The security policy follows a standard format described here:
    /// <https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md>
    /// Some CoCo enhancements have been added.
    /// For instance the `keypath` field can be set to a resource URI such as
    /// `kbs:///default/key/1`.
    ///
    /// This field points to an image security policy.
    /// The policy can either be stored in a KBS and referenced via a resource URI
    /// or it can be stored locally (somewhere in the rootfs).
    ///
    /// For example, `file:///etc/image-policy.json` for a local policy file
    /// or `kbs:///default/policies/image-security-policy.json` for a policy
    /// file that has been provisioned to a KBS.
    ///
    /// If this field is not set (which is the default) no image security policy
    /// will be used. Images will not be validated when they are pulled.
    #[serde(default = "Option::default")]
    pub image_security_policy_uri: Option<String>,

    /// The image security policy (see above) can also be specified directly
    /// as a string. If the policy URI and this field are both set,
    /// the policy URI will be used.
    #[serde(default = "Option::default")]
    pub image_security_policy: Option<String>,

    /// Sigstore config file URI for simple signing scheme.
    ///
    /// When `image_security_policy_uri` is set and `SimpleSigning` (signedBy) is
    /// used in the policy, an additional sigstore configuration file is needed.
    ///
    /// Like the above, the sigstore config can be stored locally in the rootfs
    /// or retrieved from the KBS.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub sigstore_config_uri: Option<String>,

    /// The sigstore config policy (see above) can be specified directly in the
    /// config file as a string. If the config URI and this field are both
    /// set, the config URI will be used.
    #[serde(default = "Option::default")]
    pub sigstore_config: Option<String>,

    /// To pull an image from an authenticated/private registry, credentials
    /// must be provided to image-rs. This field points to a credential file,
    /// which can either be stored locally in the rootfs or retrieved from the KBS.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub authenticated_registry_credentials_uri: Option<String>,

    /// Registry configuration supports defining registry blocking, mirroring,
    /// and remapping rules. This field points to a registry configuration file,
    /// which can either be stored locally in the rootfs or retrieved from the KBS.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub registry_configuration_uri: Option<String>,

    /// Registry configuration supports registry blocking, mirroring and remapping rules.
    /// This field points to a registry configuration file, which can either be stored locally
    /// in the rootfs or retrieved from initdata.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub registry_config: Option<RegistryConfig>,

    /// The maximum number of layers downloaded concurrently when
    /// pulling one specific image.
    ///
    /// This defaults to [`DEFAULT_MAX_CONCURRENT_DOWNLOAD`].
    #[serde(default = "default_max_concurrent_layer_downloads_per_image")]
    pub max_concurrent_layer_downloads_per_image: usize,

    /// Timeout in seconds for retrieving one image resource from the configured
    /// provider. This includes any attestation required before the provider can
    /// return a protected resource.
    #[serde(default = "default_resource_provider_timeout_secs")]
    pub resource_provider_timeout_secs: NonZeroU32,

    /// Proxy configuration for pulling images.
    #[serde(default = "Option::default")]
    pub image_pull_proxy: Option<ProxyConfig>,

    /// To pull an image from a registry with a self-signed certificate,
    /// supply the corresponding trusted root cert (in PEM format) here.
    #[serde(default = "Vec::default")]
    pub extra_root_certificates: Vec<String>,

    /// Registry hosts reached at a fixed address instead of a DNS answer
    /// (Codewire fork, codewire#4000). A pull from exactly one of these hosts
    /// connects to its address over HTTPS only, with the host still the TLS
    /// name it verifies. Only this `[image]` configuration sets them: never
    /// the kernel command line, the environment or a fetched resource.
    #[serde(default = "Vec::default")]
    pub registry_addresses: Vec<RegistryAddress>,

    #[cfg(feature = "keywrap-native")]
    #[serde(default = "default_kbc")]
    pub kbc: String,

    #[cfg(feature = "keywrap-native")]
    #[serde(default = "default_kbs_uri")]
    pub kbs_uri: String,
}

macro_rules! __default_deserialization_value {
    ($name: ident, $type: ident, $value: expr) => {
        fn $name() -> $type {
            $value
        }
    };
}

__default_deserialization_value!(
    default_max_concurrent_layer_downloads_per_image,
    usize,
    DEFAULT_MAX_CONCURRENT_DOWNLOAD
);

__default_deserialization_value!(default_work_dir, PathBuf, PathBuf::from(DEFAULT_WORK_DIR));

fn default_resource_provider_timeout_secs() -> NonZeroU32 {
    NonZeroU32::new(DEFAULT_RESOURCE_PROVIDER_TIMEOUT_SECS)
        .expect("the default resource-provider timeout must be nonzero")
}

#[cfg(feature = "keywrap-native")]
__default_deserialization_value!(default_kbc, String, "sample_kbc".into());

#[cfg(feature = "keywrap-native")]
__default_deserialization_value!(default_kbs_uri, String, "null".into());

impl Default for ImageConfig {
    // Construct a default instance of `ImageConfig`
    fn default() -> ImageConfig {
        ImageConfig {
            work_dir: PathBuf::from(DEFAULT_WORK_DIR.to_string()),
            default_snapshot: SnapshotType::default(),
            max_concurrent_layer_downloads_per_image: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            resource_provider_timeout_secs: default_resource_provider_timeout_secs(),
            image_security_policy_uri: None,
            image_security_policy: None,
            sigstore_config_uri: None,
            sigstore_config: None,
            authenticated_registry_credentials_uri: None,
            registry_configuration_uri: None,
            registry_config: None,
            image_pull_proxy: None,
            extra_root_certificates: Vec::new(),
            registry_addresses: Vec::new(),

            #[cfg(feature = "keywrap-native")]
            kbc: default_kbc(),

            #[cfg(feature = "keywrap-native")]
            kbs_uri: default_kbs_uri(),
        }
    }
}

#[derive(PartialEq, Debug)]
struct KernelParameterConfigs {
    https_proxy: Option<String>,
    http_proxy: Option<String>,
    no_proxy: Option<String>,
    authenticated_registry_credentials_uri: Option<String>,
    image_security_policy_uri: Option<String>,
    enable_signature_verification: bool,
    resource_provider_timeout_secs: Option<NonZeroU32>,
}

impl KernelParameterConfigs {
    fn new(kernel_cmdline: &str) -> Self {
        let cmdline: HashMap<&str, &str> = kernel_cmdline
            .split_ascii_whitespace()
            .filter_map(|s| s.split_once('='))
            .collect();

        Self {
            https_proxy: cmdline.get("agent.https_proxy").map(|s| s.to_string()),
            http_proxy: cmdline.get("agent.http_proxy").map(|s| s.to_string()),
            no_proxy: cmdline.get("agent.no_proxy").map(|s| s.to_string()),
            authenticated_registry_credentials_uri: cmdline
                .get("agent.image_registry_auth")
                .map(|s| s.to_string()),
            image_security_policy_uri: cmdline
                .get("agent.image_policy_file")
                .map(|s| s.to_string()),
            enable_signature_verification: cmdline
                .get("agent.enable_signature_verification")
                .map(|s| s.parse::<bool>().unwrap_or(false))
                .unwrap_or_default(),
            resource_provider_timeout_secs: cmdline
                .get("agent.image_resource_timeout_secs")
                .and_then(|value| value.parse::<NonZeroU32>().ok()),
        }
    }
}

impl TryFrom<&Path> for ImageConfig {
    /// Load `ImageConfig` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/image-rs/"
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file =
            File::open(config_path).map_err(|e| anyhow!("failed to open config file {}", e))?;

        let image_config = serde_json::from_reader::<File, ImageConfig>(file)
            .context("failed to parse config file")?;
        Ok(image_config)
    }
}

impl ImageConfig {
    /// Try read configs from kernel command line, and other items will be set as default.
    pub fn from_kernel_cmdline() -> Self {
        let mut res = ImageConfig {
            work_dir: PathBuf::from(DEFAULT_WORK_DIR.to_string()),
            default_snapshot: SnapshotType::default(),
            max_concurrent_layer_downloads_per_image: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            resource_provider_timeout_secs: default_resource_provider_timeout_secs(),
            image_security_policy_uri: None,
            image_security_policy: None,
            sigstore_config_uri: None,
            sigstore_config: None,
            authenticated_registry_credentials_uri: None,
            registry_configuration_uri: None,
            registry_config: None,
            image_pull_proxy: None,
            extra_root_certificates: Vec::new(),
            registry_addresses: Vec::new(),

            #[cfg(feature = "keywrap-native")]
            kbc: default_kbc(),

            #[cfg(feature = "keywrap-native")]
            kbs_uri: default_kbs_uri(),
        };

        if let Ok(kernel_cmdline) = fs::read_to_string("/proc/cmdline") {
            debug!("Try read image pull parameters from kernel cmdline");
            let parameters_from_kernel = KernelParameterConfigs::new(&kernel_cmdline);
            let image_pull_proxy = ProxyConfig {
                https_proxy: parameters_from_kernel.https_proxy,
                http_proxy: parameters_from_kernel.http_proxy,
                no_proxy: parameters_from_kernel.no_proxy,
            };

            res.authenticated_registry_credentials_uri =
                parameters_from_kernel.authenticated_registry_credentials_uri;
            if parameters_from_kernel.enable_signature_verification {
                res.image_security_policy_uri = parameters_from_kernel.image_security_policy_uri;
            }

            if image_pull_proxy.http_proxy.is_some()
                || image_pull_proxy.https_proxy.is_some()
                || image_pull_proxy.no_proxy.is_some()
            {
                res.image_pull_proxy = Some(image_pull_proxy);
            }

            if let Some(timeout) = parameters_from_kernel.resource_provider_timeout_secs {
                res.resource_provider_timeout_secs = timeout;
            }
        }

        res
    }

    /// Construct an instance of `ImageConfig` with specific work directory.
    pub fn new(image_work_dir: PathBuf) -> Self {
        Self {
            work_dir: image_work_dir,
            ..Default::default()
        }
    }

    /// Deadline used for resource-provider requests initiated by this image client.
    pub fn resource_provider_timeout(&self) -> Duration {
        Duration::from_secs(u64::from(self.resource_provider_timeout_secs.get()))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use std::io::prelude::*;

    #[rstest]
    #[case(
        "BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: None,
            authenticated_registry_credentials_uri: None,
            image_security_policy_uri: None,
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: None,
            image_security_policy_uri: None,
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost   \n agent.image_registry_auth=kbs:///default/credentials/test root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///default/credentials/test".into()),
            image_security_policy_uri: None,
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        agent.no_proxy=localhost   \n agent.image_registry_auth=file:///root/.docker/config.json agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("file:///root/.docker/config.json".into()),
            image_security_policy_uri: None,
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost agent.image_policy_file=kbs:///default/image-policy/test  \n agent.image_registry_auth=kbs:///a/b/c root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("kbs:///default/image-policy/test".into()),
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost agent.image_policy_file=file:///etc/image-policy.json  \n agent.image_registry_auth=kbs:///a/b/c root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("file:///etc/image-policy.json".into()),
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        agent.enable_signature_verification=true agent.no_proxy=localhost agent.image_policy_file=file:///etc/image-policy.json  \n agent.image_registry_auth=kbs:///a/b/c agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("file:///etc/image-policy.json".into()),
            enable_signature_verification: true,
            resource_provider_timeout_secs: None
        }
    )]
    #[case("
        agent.enable_signature_verification=true agent.no_proxy=localhost agent.image_policy_file=file:///etc/image-policy.json  \n agent.image_registry_auth=kbs:///a/b/c agent.https_proxy=http://1.2.3.4:1234 agent.http_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: Some("http://1.2.3.4:1234".into()),
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("file:///etc/image-policy.json".into()),
            enable_signature_verification: true,
            resource_provider_timeout_secs: None
        }
    )]
    #[case(
        "agent.image_resource_timeout_secs=300",
        KernelParameterConfigs {
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
            authenticated_registry_credentials_uri: None,
            image_security_policy_uri: None,
            enable_signature_verification: false,
            resource_provider_timeout_secs: NonZeroU32::new(300)
        }
    )]
    #[case(
        "agent.image_resource_timeout_secs=0",
        KernelParameterConfigs {
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
            authenticated_registry_credentials_uri: None,
            image_security_policy_uri: None,
            enable_signature_verification: false,
            resource_provider_timeout_secs: None
        }
    )]
    fn test_parse_kernel_parameter(
        #[case] kernel_parameter: &str,
        #[case] expected: KernelParameterConfigs,
    ) {
        let config = KernelParameterConfigs::new(kernel_parameter);
        assert_eq!(config, expected);
    }

    #[test]
    fn test_image_config() {
        let config = ImageConfig::default();
        let work_dir = PathBuf::from(DEFAULT_WORK_DIR);

        assert_eq!(config.work_dir, work_dir);
        assert_eq!(config.default_snapshot, SnapshotType::Overlay);
        assert_eq!(
            config.max_concurrent_layer_downloads_per_image,
            DEFAULT_MAX_CONCURRENT_DOWNLOAD
        );
        assert_eq!(
            config.resource_provider_timeout_secs.get(),
            DEFAULT_RESOURCE_PROVIDER_TIMEOUT_SECS
        );

        let env_work_dir = "/tmp";
        let config = ImageConfig::new(PathBuf::from(env_work_dir));
        let work_dir = PathBuf::from(env_work_dir);
        assert_eq!(config.work_dir, work_dir);
    }

    #[test]
    fn test_image_config_from_file() {
        let data = r#"{
            "work_dir": "/run/kata-containers/image/",
            "default_snapshot": "overlay",
            "image_security_policy_uri": "file:///etc/image-policy.json",
            "authenticated_registry_credentials_uri": "file:///etc/image-auth.json",
            "resource_provider_timeout_secs": 300,
	        "max_concurrent_layer_downloads_per_image": 1
        }"#;

        let tempdir = tempfile::tempdir().unwrap();
        let config_file = tempdir.path().join("config.json");

        File::create(&config_file)
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();

        let config = ImageConfig::try_from(config_file.as_path()).unwrap();
        let work_dir = PathBuf::from(DEFAULT_WORK_DIR);

        assert_eq!(config.work_dir, work_dir);
        assert_eq!(config.default_snapshot, SnapshotType::Overlay);
        assert_eq!(config.max_concurrent_layer_downloads_per_image, 1);
        assert_eq!(config.resource_provider_timeout_secs.get(), 300);
        assert_eq!(
            config.image_security_policy_uri,
            Some("file:///etc/image-policy.json".to_string())
        );
        assert_eq!(
            config.authenticated_registry_credentials_uri,
            Some("file:///etc/image-auth.json".to_string())
        );

        let invalid_config_file = tempdir.path().join("does-not-exist");
        assert!(!invalid_config_file.exists());

        let _ = ImageConfig::try_from(invalid_config_file.as_path()).is_err();
        assert!(!invalid_config_file.exists());
    }

    #[test]
    fn test_image_config_rejects_zero_resource_provider_timeout() {
        let data = r#"{
            "resource_provider_timeout_secs": 0
        }"#;
        let tempdir = tempfile::tempdir().unwrap();
        let config_file = tempdir.path().join("config.json");

        File::create(&config_file)
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();

        assert!(ImageConfig::try_from(config_file.as_path()).is_err());
    }

    fn entry(host: &str, address: &str) -> RegistryAddress {
        RegistryAddress {
            host: host.to_string(),
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn registry_addresses_come_from_the_image_table() {
        let config: ImageConfig = serde_json::from_str(
            r#"{"registry_addresses": [{"host": "registry.example", "address": "192.0.2.10"}]}"#,
        )
        .unwrap();
        assert_eq!(
            config.registry_addresses,
            vec![entry("registry.example", "192.0.2.10")]
        );
        validate_registry_addresses(&config.registry_addresses, None).unwrap();
    }

    #[test]
    fn a_registry_address_that_is_not_an_ip_is_refused() {
        let parsed = serde_json::from_str::<ImageConfig>(
            r#"{"registry_addresses": [{"host": "registry.example", "address": "registry.other"}]}"#,
        );
        assert!(parsed.is_err());
    }

    #[rstest]
    #[case::empty(vec![entry("", "10.0.0.1")])]
    #[case::ipv4_host(vec![entry("10.0.0.2", "10.0.0.1")])]
    #[case::ipv6_host(vec![entry("fd00::2", "10.0.0.1")])]
    #[case::port(vec![entry("registry.example:443", "10.0.0.1")])]
    #[case::path(vec![entry("registry.example/codewire", "10.0.0.1")])]
    #[case::twice(vec![entry("registry.example", "10.0.0.1"), entry("Registry.Example", "10.0.0.2")])]
    fn bad_registry_addresses_are_refused(#[case] addresses: Vec<RegistryAddress>) {
        assert!(validate_registry_addresses(&addresses, None).is_err());
    }

    #[test]
    fn registry_addresses_are_refused_with_an_https_proxy() {
        let addresses = vec![entry("registry.example", "192.0.2.10")];
        let https = ProxyConfig {
            https_proxy: Some("http://192.0.2.99:3128".into()),
            http_proxy: None,
            no_proxy: None,
        };
        assert!(validate_registry_addresses(&addresses, Some(&https)).is_err());
        // No addresses, no conflict; an http-only proxy never carries these
        // pulls, which are HTTPS only.
        validate_registry_addresses(&[], Some(&https)).unwrap();
        let http_only = ProxyConfig {
            https_proxy: None,
            http_proxy: Some("http://192.0.2.99:3128".into()),
            no_proxy: None,
        };
        validate_registry_addresses(&addresses, Some(&http_only)).unwrap();
    }

    #[test]
    fn only_the_exact_host_is_overridden() {
        let addresses = vec![entry("registry.example", "192.0.2.10")];
        for registry in [
            "registry.example",
            "REGISTRY.example",
            "registry.example:5000",
        ] {
            assert_eq!(
                registry_address_for(&addresses, registry).map(|e| e.address),
                Some("192.0.2.10".parse().unwrap()),
                "{registry}"
            );
        }
        for registry in [
            "registry.example.evil",
            "sub.registry.example",
            "docker.io",
            "registry.exampl",
        ] {
            assert_eq!(
                registry_address_for(&addresses, registry),
                None,
                "{registry}"
            );
        }
    }

    #[test]
    fn the_kernel_command_line_never_sets_registry_addresses() {
        assert!(ImageConfig::from_kernel_cmdline()
            .registry_addresses
            .is_empty());
        assert!(ImageConfig::default().registry_addresses.is_empty());
    }
}
