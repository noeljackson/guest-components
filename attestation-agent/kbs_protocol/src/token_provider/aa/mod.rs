// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a token provider which connects the attestation-agent

use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;
use tracing::info;
use ttrpc::context;

use crate::{Error, Result, TeeKeyPair, Token};
use protos::ttrpc::aa::{
    attestation_agent::GetTokenRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
};

use super::TokenProvider;

const AA_SOCKET_FILE: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

const TOKEN_TYPE: &str = "kbs";
const DEFAULT_AA_TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(50);

pub struct AATokenProvider {
    client: AttestationAgentServiceClient,
    request_timeout: Duration,
}

#[derive(Deserialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

impl AATokenProvider {
    pub async fn new() -> Result<Self> {
        Self::new_with_socket_and_timeout(AA_SOCKET_FILE, DEFAULT_AA_TOKEN_REQUEST_TIMEOUT).await
    }

    pub async fn new_with_socket(aa_socket: &str) -> Result<Self> {
        Self::new_with_socket_and_timeout(aa_socket, DEFAULT_AA_TOKEN_REQUEST_TIMEOUT).await
    }

    pub async fn new_with_socket_and_timeout(
        aa_socket: &str,
        request_timeout: Duration,
    ) -> Result<Self> {
        let c = ttrpc::r#async::Client::connect(aa_socket)
            .await
            .map_err(|e| Error::AATokenProvider(format!("ttrpc connect failed {e:?}")))?;
        let client = AttestationAgentServiceClient::new(c);
        info!(
            timeout_secs = request_timeout.as_secs(),
            "configured Attestation Agent token request timeout"
        );
        Ok(Self {
            client,
            request_timeout,
        })
    }
}

fn request_context(timeout: Duration) -> context::Context {
    context::with_duration(timeout)
}

#[async_trait]
impl TokenProvider for AATokenProvider {
    async fn get_token(&self) -> Result<(Token, TeeKeyPair)> {
        let req = GetTokenRequest {
            TokenType: TOKEN_TYPE.to_string(),
            ..Default::default()
        };
        let bytes = self
            .client
            .get_token(request_context(self.request_timeout), &req)
            .await
            .map_err(|e| Error::AATokenProvider(format!("cal ttrpc failed: {e:?}")))?;
        let message: Message = serde_json::from_slice(&bytes.Token).map_err(|e| {
            Error::AATokenProvider(format!("deserialize attestation-agent reply failed: {e:?}"))
        })?;
        let token = Token::new(message.token)
            .map_err(|e| Error::AATokenProvider(format!("deserialize token failed: {e:?}")))?;
        let tee_keypair = TeeKeyPair::from_pem(&message.tee_keypair).map_err(|e| {
            Error::AATokenProvider(format!("deserialize tee keypair failed: {e:?}"))
        })?;
        Ok((token, tee_keypair))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_request_context_uses_selected_timeout() {
        assert_eq!(
            request_context(Duration::from_secs(300)).timeout_nano,
            300_000_000_000
        );
    }

    #[test]
    fn default_token_request_timeout_remains_compatible() {
        assert_eq!(
            request_context(DEFAULT_AA_TOKEN_REQUEST_TIMEOUT).timeout_nano,
            50_000_000_000
        );
    }
}
