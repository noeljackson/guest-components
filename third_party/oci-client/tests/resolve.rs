//! `ClientConfig::resolve` (Codewire fork, codewire#4000): a named registry
//! host reached at a fixed address, against local TLS servers.
//!
//! The certificates under `tests/fixtures/resolve` come from a throwaway test
//! CA whose key was discarded: `registry.test` and `other.test`, each with
//! only that DNS name.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oci_client::client::{Certificate, CertificateEncoding, ClientConfig};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{crypto, ServerConfig};
use tokio_rustls::TlsAcceptor;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/resolve");
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// What a test server answers, from the request line.
type Respond = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A TLS server on 127.0.0.1 presenting `name`'s certificate. Each request's
/// head is recorded; every response closes its connection.
async fn serve(name: &str, respond: Respond) -> (u16, Arc<Mutex<Vec<String>>>) {
    let chain = CertificateDer::pem_file_iter(format!("{FIXTURES}/{name}.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(format!("{FIXTURES}/{name}.key")).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let respond = respond.clone();
            let record = record.clone();
            tokio::spawn(async move {
                // A handshake the client refuses ends here.
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let line = head.lines().next().unwrap_or_default().to_string();
                record.lock().unwrap().push(head);
                let _ = tls.write_all(respond(&line).as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, seen)
}

fn ok_manifest() -> Respond {
    Arc::new(|line: &str| {
        if line.starts_with("GET /v2/ ") {
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_string()
        } else {
            format!(
                "HTTP/1.1 200 OK\r\ndocker-content-digest: {DIGEST}\r\n\
                 content-type: application/vnd.oci.image.manifest.v1+json\r\n\
                 content-length: 0\r\nconnection: close\r\n\r\n"
            )
        }
    })
}

fn client(resolve: Vec<(String, IpAddr)>) -> Client {
    Client::new(ClientConfig {
        resolve,
        extra_root_certificates: vec![Certificate {
            encoding: CertificateEncoding::Pem,
            data: std::fs::read(format!("{FIXTURES}/ca.pem")).unwrap(),
        }],
        ..Default::default()
    })
}

/// Every client call is bounded, so a regression fails instead of hanging.
/// `None` means the call didn't finish in time.
async fn fetch(
    client: &Client,
    reference: &Reference,
    auth: &RegistryAuth,
) -> Option<oci_client::errors::Result<String>> {
    tokio::time::timeout(
        Duration::from_secs(10),
        client.fetch_manifest_digest(reference, auth),
    )
    .await
    .ok()
}

fn reference(host: &str, port: u16) -> Reference {
    format!("{host}:{port}/codewire/daemon:test")
        .parse()
        .unwrap()
}

#[tokio::test]
async fn a_named_host_is_reached_at_its_address_and_verified_by_its_name() {
    let (port, seen) = serve("registry.test", ok_manifest()).await;
    let client = client(vec![("registry.test".to_string(), LOCALHOST)]);
    let digest = fetch(
        &client,
        &reference("registry.test", port),
        &RegistryAuth::Anonymous,
    )
    .await
    .expect("bounded")
    .unwrap();
    assert_eq!(digest, DIGEST);
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .all(|head| head.contains("host: registry.test")));
}

#[tokio::test]
async fn a_certificate_for_another_name_at_the_address_is_refused() {
    let (port, seen) = serve("other.test", ok_manifest()).await;
    let client = client(vec![("registry.test".to_string(), LOCALHOST)]);
    let result = fetch(
        &client,
        &reference("registry.test", port),
        &RegistryAuth::Anonymous,
    )
    .await;
    assert!(matches!(result, Some(Err(_))), "{result:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "a request was sent over the refused connection"
    );
}

#[tokio::test]
async fn an_unnamed_host_is_not_overridden() {
    let (port, seen) = serve("registry.test", ok_manifest()).await;
    let client = client(vec![("other.test".to_string(), LOCALHOST)]);
    // registry.test isn't in the list, so it needs DNS, which has no answer;
    // a slow resolver may leave the call unfinished, which is also a miss.
    let result = fetch(
        &client,
        &reference("registry.test", port),
        &RegistryAuth::Anonymous,
    )
    .await;
    assert!(!matches!(result, Some(Ok(_))), "{result:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "the unnamed host reached the fixed address"
    );
}

#[tokio::test]
async fn a_redirect_to_http_is_never_followed() {
    let plain = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let plain_port = plain.local_addr().unwrap().port();
    let respond: Respond = Arc::new(move |line: &str| {
        if line.starts_with("GET /v2/ ") {
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_string()
        } else {
            format!(
                "HTTP/1.1 302 Found\r\nlocation: http://registry.test:{plain_port}/v2/x\r\n\
                 content-length: 0\r\nconnection: close\r\n\r\n"
            )
        }
    });
    let followed = Arc::new(AtomicBool::new(false));
    let flag = followed.clone();
    tokio::spawn(async move {
        if plain.accept().await.is_ok() {
            flag.store(true, Ordering::SeqCst);
        }
    });
    let (port, _) = serve("registry.test", respond).await;
    let client = client(vec![("registry.test".to_string(), LOCALHOST)]);
    let result = fetch(
        &client,
        &reference("registry.test", port),
        &RegistryAuth::Anonymous,
    )
    .await;
    assert!(
        !followed.load(Ordering::SeqCst),
        "the client followed the redirect to http"
    );
    assert!(matches!(result, Some(Err(_))), "{result:?}");
}

#[tokio::test]
async fn authorization_is_not_carried_to_another_host() {
    let (other_port, other_seen) = serve("other.test", ok_manifest()).await;
    let respond: Respond = Arc::new(move |line: &str| {
        format!(
            "HTTP/1.1 307 Temporary Redirect\r\nlocation: https://other.test:{other_port}{}\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n",
            line.split(' ').nth(1).unwrap_or("/")
        )
    });
    let (port, seen) = serve("registry.test", respond).await;
    let client = client(vec![
        ("registry.test".to_string(), LOCALHOST),
        ("other.test".to_string(), LOCALHOST),
    ]);
    let digest = fetch(
        &client,
        &reference("registry.test", port),
        &RegistryAuth::Bearer("secret-token".to_string()),
    )
    .await
    .expect("bounded")
    .unwrap();
    assert_eq!(digest, DIGEST);
    let to_registry = seen.lock().unwrap().clone();
    assert!(
        to_registry.iter().any(|head| head
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-token")),
        "the registry got no Authorization, so this test proves nothing: {to_registry:?}"
    );
    let to_other = other_seen.lock().unwrap().clone();
    assert!(!to_other.is_empty(), "the redirect wasn't followed");
    assert!(
        to_other
            .iter()
            .all(|head| !head.to_ascii_lowercase().contains("authorization:")),
        "Authorization reached another host: {to_other:?}"
    );
}

#[tokio::test]
async fn a_proxy_from_the_environment_is_not_used() {
    // A proxy nothing listens on: a client that used it would fail.
    let dead = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let (port, _) = serve("registry.test", ok_manifest()).await;
    std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{dead_port}"));
    let client = client(vec![("registry.test".to_string(), LOCALHOST)]);
    std::env::remove_var("HTTPS_PROXY");
    let digest = fetch(
        &client,
        &reference("registry.test", port),
        &RegistryAuth::Anonymous,
    )
    .await
    .expect("bounded")
    .unwrap();
    assert_eq!(digest, DIGEST);
}
