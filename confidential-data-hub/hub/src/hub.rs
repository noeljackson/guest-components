// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

/// Base directory for CDH runtime data.
pub(crate) const CDH_BASE_DIR: &str = "/run/confidential-containers/cdh";

use async_trait::async_trait;
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use kms::{Annotations, ProviderSettings};
use resource_uri::{ResourceUri, DEFAULT_RESOURCE_PLUGIN};
use tokio::sync::{Mutex, OnceCell};
use tracing::{debug, info, warn};

#[cfg(feature = "ttrpc")]
use protos::ttrpc::aa::attestation_agent::{
    ExtendRuntimeMeasurementRequest, RuntimeMeasurementResult,
};
#[cfg(feature = "ttrpc")]
use protos::ttrpc::aa::attestation_agent_ttrpc::AttestationAgentServiceClient;

use crate::storage::volume_type::Storage;
use crate::{image, secret, CdhConfig, DataHub, Error, Result};

struct ResourceClient {
    inner: OnceCell<Box<dyn kms::Getter>>,
}

#[derive(Debug, Default)]
struct ProtectedResourcePrefixes(Vec<Vec<String>>);

impl ProtectedResourcePrefixes {
    fn from_config(prefixes: &[String]) -> std::result::Result<Self, String> {
        prefixes
            .iter()
            .map(|prefix| {
                let resource = ResourceUri::try_from(prefix.as_str())
                    .map_err(|_| "protected resource prefix is not a KBS URI".to_string())?;
                if resource.plugin() != DEFAULT_RESOURCE_PLUGIN
                    || !resource.kbs_address.is_empty()
                    || resource.query.is_some()
                    || resource.whole_uri() != *prefix
                    || resource.path.len() < 2
                    || resource.path.last().is_none_or(|segment| !segment.is_empty())
                    || resource.path[..resource.path.len() - 1]
                        .iter()
                        .any(String::is_empty)
                {
                    return Err(
                        "protected resource prefix must be a canonical local, query-free kbs URI ending in /"
                            .to_string(),
                    );
                }

                Ok(resource.path[..resource.path.len() - 1].to_vec())
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(Self)
    }

    fn allows(&self, uri: &str) -> bool {
        self.canonical_resource(uri)
            .is_some_and(|resource| !self.protects_resource(&resource))
    }

    fn protects(&self, uri: &str) -> bool {
        self.canonical_resource(uri)
            .is_some_and(|resource| self.protects_resource(&resource))
    }

    fn canonical_resource(&self, uri: &str) -> Option<ResourceUri> {
        let Ok(resource) = ResourceUri::try_from(uri) else {
            return None;
        };
        if resource.plugin() != DEFAULT_RESOURCE_PLUGIN
            || !resource.kbs_address.is_empty()
            || resource.query.is_some()
            || resource.whole_uri() != uri
            || resource.path.iter().any(String::is_empty)
        {
            return None;
        }

        Some(resource)
    }

    fn protects_resource(&self, resource: &ResourceUri) -> bool {
        self.0
            .iter()
            .any(|prefix| resource.path.starts_with(prefix))
    }
}

impl ResourceClient {
    const fn new() -> Self {
        Self {
            inner: OnceCell::const_new(),
        }
    }

    async fn get(&self, uri: &str) -> Result<Vec<u8>> {
        // Provider settings are not required for the in-guest KBS client. Keep
        // the client for the Hub lifetime: it owns only the attested session,
        // while each returned resource remains scoped to this call.
        let client = self
            .inner
            .get_or_try_init(|| async {
                kms::new_getter("kbs", ProviderSettings::default())
                    .await
                    .map_err(|e| Error::KbsClient { source: e })
            })
            .await?;

        client
            .get_secret(uri, &Annotations::default())
            .await
            .map_err(|e| Error::GetResource { source: e })
    }

    #[cfg(test)]
    fn with_client(client: Box<dyn kms::Getter>) -> Self {
        Self {
            inner: OnceCell::new_with(Some(client)),
        }
    }
}

fn secure_volume_resource_error(stage: &'static str, source: Error) -> Error {
    let reason = match &source {
        Error::KbsClient { .. } => "client_initialization",
        Error::GetResource { .. } => "resource_request",
        _ => "unexpected",
    };
    Error::SecureVolumeResource {
        stage,
        reason,
        source: Box::new(source),
    }
}

pub struct Hub {
    #[allow(dead_code)]
    pub(crate) credentials: HashMap<String, String>,
    image_client: OnceCell<Mutex<ImageClient>>,
    // A secure-volume activation reads a content-bound manifest and then its
    // recovery key. Reuse one guest-scoped KBS client so both reads share the
    // same attested token and TEE keypair instead of performing a second
    // attestation in the middle of one activation transaction.
    resource_client: ResourceClient,
    protected_resource_prefixes: ProtectedResourcePrefixes,
    #[cfg(feature = "ttrpc")]
    aa_client: OnceCell<Option<AttestationAgentServiceClient>>,
    config: CdhConfig,
    secure_volumes: crate::storage::secure_volume::Manager,
}

impl Hub {
    pub async fn new(config: CdhConfig) -> Result<Self> {
        let protected_resource_prefixes =
            ProtectedResourcePrefixes::from_config(&config.protected_resource_uri_prefixes)
                .map_err(|error| Error::InitializationFailed(error.to_string()))?;
        config
            .set_configuration_envs()
            .map_err(|e| Error::InitializationFailed(format!("set configuration envs: {e:?}")))?;
        let credentials = config
            .credentials
            .iter()
            .map(|it| (it.path.clone(), it.resource_uri.clone()))
            .collect();

        let mut hub = Self {
            credentials,
            config,
            image_client: OnceCell::const_new(),
            resource_client: ResourceClient::new(),
            protected_resource_prefixes,
            #[cfg(feature = "ttrpc")]
            aa_client: OnceCell::const_new(),
            secure_volumes: crate::storage::secure_volume::Manager::default(),
        };

        hub.init().await?;
        Ok(hub)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        info!("unseal secret called");

        let res = secret::unseal_secret(&secret).await?;

        Ok(res)
    }

    async fn unwrap_key(&self, annotation_packet: &[u8]) -> Result<Vec<u8>> {
        info!("unwrap key called");

        let lek = image::unwrap_key(annotation_packet).await?;
        Ok(lek)
    }

    async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        info!("get resource called: {uri}");
        self.resource_client.get(&uri).await
    }

    async fn get_public_resource(&self, uri: String) -> Result<Vec<u8>> {
        if !self.protected_resource_prefixes.allows(&uri) {
            warn!("public resource request denied by policy");
            return Err(Error::PublicResourceDenied);
        }
        info!("public get resource called");
        self.resource_client.get(&uri).await
    }

    async fn secure_mount(&self, storage: Storage) -> Result<String> {
        info!("secure mount called");
        let res = storage.mount().await?;
        Ok(res)
    }

    async fn activate_volume(
        &self,
        device_id: &str,
        manifest_uri: &str,
        requested_access: crate::storage::secure_volume::VolumeAccess,
    ) -> Result<crate::storage::secure_volume::Activation> {
        use crate::storage::secure_volume::{validate_kbs_resource_uri, Manifest};
        use zeroize::Zeroizing;

        validate_kbs_resource_uri(manifest_uri)?;
        let manifest_bytes = self
            .resource_client
            .get(manifest_uri)
            .await
            .map_err(|error| secure_volume_resource_error("manifest_fetch", error))?;
        let manifest = Manifest::parse_bound(&manifest_bytes, manifest_uri)?;
        manifest.ensure_access(requested_access)?;
        if !self
            .protected_resource_prefixes
            .protects(&manifest.protection.key_uri)
        {
            return Err(crate::storage::secure_volume::Error::InvalidManifest(
                "secure-volume key URI must belong to a configured protected resource namespace"
                    .to_string(),
            )
            .into());
        }
        let key = self
            .resource_client
            .get(&manifest.protection.key_uri)
            .await
            .map(Zeroizing::new)
            .map_err(|error| secure_volume_resource_error("key_fetch", error))?;
        manifest.verify_key(&key)?;
        self.secure_volumes
            .activate(device_id, &manifest, requested_access, key)
            .await
            .map_err(Into::into)
    }

    async fn deactivate_volume(&self, activation_id: &str) -> Result<()> {
        self.secure_volumes
            .deactivate(activation_id)
            .await
            .map_err(Into::into)
    }

    async fn pull_image(&self, image_url: &str, bundle_path: &str) -> Result<String> {
        let client = self
            .image_client
            .get_or_try_init(
                || async move { initialize_image_client(self.config.image.clone()).await },
            )
            .await?;

        let image_info = client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await?;

        #[cfg(not(feature = "ttrpc"))]
        warn!(
            "`ttrpc` feature is not enabled, so all runtime measurement extension will be skipped."
        );

        #[cfg(feature = "ttrpc")]
        {
            use anyhow::anyhow;
            use ttrpc::context::with_timeout;

            // 10 seconds in nanoseconds
            const EXTEND_RUNTIME_MEASUREMENT_TIMEOUT: i64 = 10 * 1000 * 1000 * 1000;

            let aa_client = self
                .aa_client
                .get_or_try_init(
                    || async move { initialize_aa_client(&self.config.aa.aa_socket).await },
                )
                .await?;

            let Some(aa_client) = aa_client else {
                warn!("Attestation Agent socket file not found, so all runtime measurement extension will be skipped.");
                return Ok(image_info.manifest_digest);
            };

            info!("Extend image pull event via AA's runtime measurement API...");
            debug!("The pulled image information: {image_info:?}");
            // The event follows definition in
            // https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md#confidential-containers-event-spec
            let req = ExtendRuntimeMeasurementRequest {
                Domain: "github.com/confidential-containers".to_string(),
                Operation: "PullImage".to_string(),
                Content: format!(
                    r#"{{"image":"{image_url}", "digest":"{}"}}"#,
                    image_info.manifest_digest
                ),
                ..Default::default()
            };
            let res = aa_client
                .extend_runtime_measurement(with_timeout(EXTEND_RUNTIME_MEASUREMENT_TIMEOUT), &req)
                .await
                .map_err(|e| Error::AttestationAgentClientError {
                    source: anyhow!("failed to extend runtime measurement: {e:?}"),
                })?;

            match res
                .Result
                .enum_value()
                .map_err(|e| Error::AttestationAgentClientError {
                    source: anyhow!("failed to get runtime measurement result: {e:?}"),
                })? {
                RuntimeMeasurementResult::OK => {
                    info!("image pull event extended runtime measurement successfully");
                }
                RuntimeMeasurementResult::NOT_SUPPORTED => {
                    warn!("Current platform does not support runtime measurement, skipping runtime measurement extension.")
                }
                RuntimeMeasurementResult::NOT_ENABLED => {
                    warn!("Runtime measurement is not enabled in Attestation Agent configuration, skipping runtime measurement extension.")
                }
            }
        }

        Ok(image_info.manifest_digest)
    }
}

async fn initialize_image_client(config: ImageConfig) -> Result<Mutex<ImageClient>> {
    debug!("Image client lazy initializing...");

    let image_client = Into::<ClientBuilder>::into(config).build().await?;

    Ok(Mutex::new(image_client))
}

#[cfg(feature = "ttrpc")]
async fn initialize_aa_client(aa_socket: &str) -> Result<Option<AttestationAgentServiceClient>> {
    use anyhow::anyhow;

    let socket_path = aa_socket.strip_prefix("unix://").unwrap_or(aa_socket);
    if !Path::new(socket_path).exists() {
        return Ok(None);
    }

    let c = ttrpc::r#async::Client::connect(aa_socket)
        .await
        .map_err(|e| Error::AttestationAgentClientError {
            source: anyhow!("failed to connect to attestation agent: {e:?}"),
        })?;
    let client = AttestationAgentServiceClient::new(c);
    Ok(Some(client))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use crate::{AaConfig, KbsConfig, LogConfig};
    use sha2::{Digest, Sha256};

    const VOLUME_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    struct StatefulGetter {
        calls: Arc<AtomicUsize>,
    }

    struct SequenceGetter {
        calls: Arc<AtomicUsize>,
        resources: Vec<Vec<u8>>,
    }

    #[async_trait]
    impl kms::Getter for StatefulGetter {
        async fn get_secret(
            &self,
            _name: &str,
            _annotations: &Annotations,
        ) -> kms::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(call.to_string().into_bytes())
        }
    }

    #[async_trait]
    impl kms::Getter for SequenceGetter {
        async fn get_secret(
            &self,
            _name: &str,
            _annotations: &Annotations,
        ) -> kms::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            self.resources
                .get(call)
                .cloned()
                .ok_or_else(|| kms::Error::KbsClientError("unexpected resource fetch".into()))
        }
    }

    fn test_hub(client: Box<dyn kms::Getter>, prefixes: Vec<String>) -> Hub {
        Hub {
            credentials: HashMap::new(),
            image_client: OnceCell::const_new(),
            resource_client: ResourceClient::with_client(client),
            protected_resource_prefixes: ProtectedResourcePrefixes::from_config(&prefixes).unwrap(),
            #[cfg(feature = "ttrpc")]
            aa_client: OnceCell::const_new(),
            config: CdhConfig {
                kbc: KbsConfig {
                    name: "offline_fs_kbc".to_string(),
                    url: String::new(),
                    kbs_cert: None,
                },
                aa: AaConfig::default(),
                credentials: vec![],
                image: ImageConfig::default(),
                socket: String::new(),
                protected_resource_uri_prefixes: prefixes,
                skip_sealed_secret_verification: false,
                log: LogConfig::default(),
            },
            secure_volumes: crate::storage::secure_volume::Manager::default(),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn secure_volume_fixture(key_uri: &str) -> (Vec<u8>, String) {
        let key_digest = sha256_hex(VOLUME_KEY);
        let manifest = format!(
            r#"{{
              "schemaVersion": 3,
              "volumeId": "tenant/workload/volume-1",
              "volumeVersion": "volume-1-v2",
              "deviceSizeBytes": 1073741824,
              "access": "readWrite",
              "protection": {{
                "type": "luks2-integrity-rw",
                "profileVersion": 1,
                "keyUri": "{key_uri}",
                "keySha256": "{key_digest}",
                "luksUuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
              }}
            }}"#
        )
        .into_bytes();
        let manifest_digest = sha256_hex(&manifest);
        let manifest_uri = format!("kbs:///tenant/storage-manifests/sha256-{manifest_digest}");
        (manifest, manifest_uri)
    }

    #[tokio::test]
    async fn resource_client_reuses_one_attested_session() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = ResourceClient::with_client(Box::new(StatefulGetter {
            calls: calls.clone(),
        }));

        assert_eq!(
            client.get("kbs:///default/manifests/one").await.unwrap(),
            b"1"
        );
        assert_eq!(client.get("kbs:///default/keys/one").await.unwrap(), b"2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn public_resource_guard_blocks_keys_without_affecting_internal_reads() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prefixes = vec!["kbs:///default/volume-keys/".to_string()];
        let hub = test_hub(
            Box::new(StatefulGetter {
                calls: calls.clone(),
            }),
            prefixes,
        );

        let key_uri = "kbs:///default/volume-keys/workspace-1";
        assert!(matches!(
            hub.get_public_resource(key_uri.to_string()).await,
            Err(Error::PublicResourceDenied)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        assert_eq!(hub.get_resource(key_uri.to_string()).await.unwrap(), b"1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn protected_resource_prefixes_compare_canonical_path_segments() {
        let prefixes =
            ProtectedResourcePrefixes::from_config(&["kbs:///default/volume-keys/".to_string()])
                .unwrap();

        assert!(!prefixes.allows("kbs:///default/volume-keys/workspace-1"));
        assert!(!prefixes.allows("kbs:///default/%76olume-keys/workspace-1"));
        assert!(prefixes.allows("kbs:///default/volume-keys-backup/workspace-1"));
        assert!(prefixes.allows("kbs:///default/manifests/workspace-1"));
        assert!(!prefixes.allows("kbs://remote.example/default/manifests/workspace-1"));
        assert!(!prefixes.allows("not-a-resource-uri"));

        assert!(prefixes.protects("kbs:///default/volume-keys/workspace-1"));
        assert!(!prefixes.protects("kbs:///default/%76olume-keys/workspace-1"));
        assert!(!ProtectedResourcePrefixes::default()
            .protects("kbs:///default/volume-keys/workspace-1"));
    }

    #[test]
    fn protected_resource_prefixes_reject_ambiguous_configuration() {
        for prefix in [
            "kbs:///default/volume-keys",
            "kbs:///default//",
            "kbs://remote.example/default/volume-keys/",
            "kbs:///default/volume-keys/?query=value",
            "kbs:///default/%76olume-keys/",
        ] {
            assert!(
                ProtectedResourcePrefixes::from_config(&[prefix.to_string()]).is_err(),
                "accepted ambiguous protected prefix {prefix}"
            );
        }
    }

    #[tokio::test]
    async fn secure_volume_requires_a_configured_protected_key_namespace() {
        let key_uri = "kbs:///tenant/storage-keys/volume-1-v1";

        for prefixes in [vec![], vec!["kbs:///tenant/other-keys/".to_string()]] {
            let (manifest, manifest_uri) = secure_volume_fixture(key_uri);
            let calls = Arc::new(AtomicUsize::new(0));
            let hub = test_hub(
                Box::new(SequenceGetter {
                    calls: calls.clone(),
                    resources: vec![manifest, VOLUME_KEY.to_vec()],
                }),
                prefixes,
            );

            let error = hub
                .activate_volume(
                    "invalid-device",
                    &manifest_uri,
                    crate::storage::secure_volume::VolumeAccess::ReadWrite,
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                Error::SecureVolume(crate::storage::secure_volume::Error::InvalidManifest(_))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 1, "key must not be fetched");
        }
    }

    #[tokio::test]
    async fn secure_volume_fetches_a_key_only_from_the_protected_namespace() {
        let key_uri = "kbs:///tenant/storage-keys/volume-1-v1";
        let (manifest, manifest_uri) = secure_volume_fixture(key_uri);
        let calls = Arc::new(AtomicUsize::new(0));
        let hub = test_hub(
            Box::new(SequenceGetter {
                calls: calls.clone(),
                resources: vec![manifest, VOLUME_KEY.to_vec()],
            }),
            vec!["kbs:///tenant/storage-keys/".to_string()],
        );

        let error = hub
            .activate_volume(
                "invalid-device",
                &manifest_uri,
                crate::storage::secure_volume::VolumeAccess::ReadWrite,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::SecureVolume(crate::storage::secure_volume::Error::InvalidDevice(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
