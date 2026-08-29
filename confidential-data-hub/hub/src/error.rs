// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{image, secret, storage};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kbs client initialization failed")]
    KbsClient {
        #[source]
        source: kms::Error,
    },

    #[error("Get Resource failed: {source}")]
    GetResource {
        #[source]
        source: kms::Error,
    },

    #[error("Public resource access denied")]
    PublicResourceDenied,

    #[error("Decrypt Image (UnwrapKey) failed")]
    ImageDecryption(#[from] image::Error),

    #[error("init Hub failed: {0}")]
    InitializationFailed(String),

    #[error("Unseal Secret failed")]
    UnsealSecret(#[from] secret::SecretError),

    #[error("Secure Mount failed")]
    SecureMount(#[from] storage::Error),

    #[error("Secure Volume failed")]
    SecureVolume(#[from] storage::secure_volume::Error),

    #[error("Secure Volume {stage} failed")]
    SecureVolumeResource {
        stage: &'static str,
        reason: &'static str,
        #[source]
        source: Box<Error>,
    },

    #[error("Image Pull error: {0}")]
    ImagePull(#[from] image_rs::image::PullImageError),

    #[error("Image Client error: {0}")]
    ImageClient(#[from] image_rs::builder::BuilderError),

    #[error("Attestation Agent client error: {source}")]
    AttestationAgentClientError {
        #[source]
        source: anyhow::Error,
    },
}

impl Error {
    pub fn secure_volume_failure(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::SecureVolume(error) => Some(error.failure_code()),
            Self::SecureVolumeResource { stage, reason, .. } => Some((stage, reason)),
            _ => None,
        }
    }

    pub fn secure_volume_status_message(&self) -> String {
        match self.secure_volume_failure() {
            Some((stage, reason)) => format!(
                "[CDH] [ERROR]: secure volume activation failed; stage={stage}; reason={reason}"
            ),
            None => format!("[CDH] [ERROR]: {self}"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use image_rs::signature::SignatureError;
    use image_rs::{
        image::PullImageError,
        pull::PullLayerError,
        stream::{StreamError, UnpackError},
    };
    use rstest::rstest;
    use std::io;

    #[rstest]
    #[case(Error::KbsClient { source: kms::Error::KbsClientError("details".into()) }, "kbs client initialization failed")]
    #[case(Error::GetResource { source: kms::Error::KbsClientError("details".into()) }, "Get Resource failed: Kbs client error: details")]
    #[case(Error::PublicResourceDenied, "Public resource access denied")]
    #[case(
        Error::UnsealSecret(secret::SecretError::VersionError),
        "Unseal Secret failed"
    )]
    #[case(
        Error::SecureMount(storage::Error::StorageTypeNotRecognized(
            strum::ParseError::VariantNotFound
        )),
        "Secure Mount failed"
    )]
    #[case(Error::ImagePull(image_rs::image::PullImageError::SignatureValidationFailed(SignatureError::DeniedByPolicy { source: anyhow!("some details")})), "Image Pull error: Image policy rejected: Denied by policy: some details")]
    fn test_brief_message(#[case] error: Error, #[case] expected: &str) {
        let brief_message = error.to_string();
        assert_eq!(brief_message, expected);
    }

    #[test]
    fn image_pull_unpack_error_preserves_io_cause() {
        let source = io::Error::from(io::ErrorKind::PermissionDenied);
        let source_message = source.to_string();
        let error = Error::ImagePull(PullImageError::PullLayersFailed(
            PullLayerError::HandleStreamError(StreamError::UnPackLayerFailed(
                UnpackError::UnpackFailed { source },
            )),
        ));

        let message = error.to_string();
        assert!(message.contains("Failed to unpack layer to destination"));
        assert!(message.contains(&source_message));
    }

    #[test]
    fn secure_volume_status_is_bounded_and_stage_specific() {
        let error = Error::SecureVolume(storage::secure_volume::Error::AccessMismatch {
            requested: storage::secure_volume::VolumeAccess::ReadOnly,
            manifest: storage::secure_volume::VolumeAccess::ReadWrite,
        });

        assert_eq!(
            error.secure_volume_status_message(),
            "[CDH] [ERROR]: secure volume activation failed; stage=access_validation; reason=mismatch"
        );
    }

    #[test]
    fn secure_volume_resource_status_omits_provider_detail() {
        let error = Error::SecureVolumeResource {
            stage: "key_fetch",
            reason: "client_initialization",
            source: Box::new(Error::KbsClient {
                source: kms::Error::KbsClientError("sensitive provider detail".into()),
            }),
        };

        let status = error.secure_volume_status_message();
        assert_eq!(
            status,
            "[CDH] [ERROR]: secure volume activation failed; stage=key_fetch; reason=client_initialization"
        );
        assert!(!status.contains("sensitive provider detail"));
    }
}
