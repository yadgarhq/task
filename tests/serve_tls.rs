//! The serving side of the transport, proved by real handshakes.
//!
//! **A test that only shows "TLS was configured" passes against the broken
//! version of this change**, so nothing here inspects configuration. Every case
//! stands up this service's own listener through [`yadgar_task::serve::builder`]
//! — the single function `main` builds its server with — and asks whether a
//! request survived the transport.
//!
//! THE DEFECT THIS CAR EXISTS TO REMOVE is a listener that opens in cleartext
//! because TLS configuration failed. `a_tls_listener_refuses_a_cleartext_client`
//! is the case that notices: it is the only one that fails if `builder` ever
//! answers a bad identity with a plain `Server::builder()`.
//!
//! ALPN IS PROVED RATHER THAN ASSUMED, and by tonic's client rather than by an
//! assertion written here. `tonic::transport::Endpoint` errors when the
//! negotiated protocol is not `h2` and `assume_http2` is unset, which it is by
//! default — so a channel that connects and carries a request has negotiated
//! `h2`. The push of `h2` into the acceptor's ALPN list is tonic's own; there is
//! no line in this repository to mutate, and saying so is more honest than
//! dressing it as coverage.
//!
//! CERTIFICATES ARE MINTED PER RUN. A fixture key committed to the repository is
//! a secret committed to the repository, and it expires on a date nobody is
//! watching.
//!
//! NOTE ON `localhost`: on this machine it resolves to BOTH `::1` and
//! `127.0.0.1`, so a rig that binds one of them is flaky by construction — the
//! client picks an address the server is not on. [`serve_on_localhost`] binds
//! every address the name resolves to, on one port. That is a property of the
//! rig, not of the service.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use yadgar_task::serve::{self, ServeTls, ServeTlsError, LISTEN};

/// The name the test certificates are issued for, and the name the rig listens
/// on.
const SERVED_NAME: &str = "localhost";

/// A certificate authority and one certificate it issued.
struct Pki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

/// Mint a CA and a server certificate for `san`.
fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-task test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &ca).unwrap();

    Pki {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A file that deletes itself, so a certificate and a key can be handed over as
/// PATHS — which is the only shape [`ServeTls`] accepts, and the reason it
/// accepts it (D80).
struct TempPem(PathBuf);

impl TempPem {
    fn with(contents: &str) -> Self {
        let name = format!(
            "yadgar-task-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build a [`ServeTls`] through the SAME lookup seam `main` reads the
/// environment with, so the tests exercise the shipped path rather than a
/// constructor built for them.
fn serve_tls(cert: &Path, key: &Path) -> ServeTls {
    let cert = cert.display().to_string();
    let key = key.display().to_string();
    ServeTls::from_lookup(LISTEN, |k| match k {
        "LISTEN_TLS_ENABLED" => Some("1".to_string()),
        "LISTEN_TLS_CERT_FILE" => Some(cert.clone()),
        "LISTEN_TLS_KEY_FILE" => Some(key.clone()),
        _ => None,
    })
    .expect("a certificate and a key enable TLS")
    .expect("the flag is set")
}

/// Serve gRPC on every address `SERVED_NAME` resolves to, and return the shared
/// port. `Routes::default()` answers every method with `Unimplemented`, which is
/// the whole of what these tests need: the question each asks is whether a
/// request reached the server at all.
async fn serve_on_localhost(tls: Option<&ServeTls>) -> u16 {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty(), "{SERVED_NAME} resolved to nothing");

    let first = TcpListener::bind(addrs[0]).await.unwrap();
    let port = first.local_addr().unwrap().port();
    spawn(first, tls);

    for addr in &addrs[1..] {
        let listener = TcpListener::bind(SocketAddr::new(addr.ip(), port))
            .await
            .expect("the same free port on a second address of the same name");
        spawn(listener, tls);
    }

    ready(port).await;
    port
}

fn spawn(listener: TcpListener, tls: Option<&ServeTls>) {
    let mut builder = serve::builder(tls).expect("a usable identity");
    let router = builder.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

/// Wait until the port accepts a TCP connection, rather than sleeping a guessed
/// interval.
async fn ready(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((SERVED_NAME, port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test server never accepted a connection on port {port}");
}

/// Send one gRPC request down the channel and report the HTTP status it came
/// back with.
///
/// `Ok(200)` means the transport carried it: the handshake completed and the
/// server answered — with `Unimplemented`, which is a perfectly good answer to
/// this question. `Err` means it never got there.
async fn request(mut channel: Channel) -> Result<u16, String> {
    let req = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!(
            "https://{SERVED_NAME}/yadgar.taskapi.v1.TaskService/Probe"
        ))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .unwrap();

    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), channel.call(req)).await {
        Err(_) => Err("the request timed out".to_string()),
        Ok(Ok(response)) => Ok(response.status().as_u16()),
        Ok(Err(e)) => Err(format!("{e}")),
    }
}

/// Reach the listener the way a TLS client does, verifying against `ca_pem`.
async fn over_tls(port: u16, ca_pem: &str) -> Result<u16, String> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(SERVED_NAME);
    let channel = Endpoint::from_shared(format!("https://{SERVED_NAME}:{port}"))
        .unwrap()
        .tls_config(tls)
        .map_err(|e| format!("{e}"))?
        .connect()
        .await
        .map_err(|e| format!("{e}"))?;
    request(channel).await
}

/// Reach the listener the way every client in the estate does today.
async fn in_cleartext(port: u16) -> Result<u16, String> {
    let channel = Endpoint::from_shared(format!("http://{SERVED_NAME}:{port}"))
        .unwrap()
        .connect()
        .await
        .map_err(|e| format!("{e}"))?;
    request(channel).await
}

/// THE POINT OF THE CAR: a client speaking TLS gets an answer, so the hop can
/// be encrypted at all. HTTP 200 with a gRPC `Unimplemented` in it is what a
/// completed handshake plus a negotiated `h2` looks like.
#[tokio::test]
async fn a_tls_listener_answers_a_tls_client() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve_on_localhost(Some(&serve_tls(cert.path(), key.path()))).await;

    assert_eq!(over_tls(port, &p.ca_pem).await, Ok(200));
}

/// THE SILENT DOWNGRADE, in the only form a test can see it. Every other case
/// here would still pass against a `builder` that answered an unusable identity
/// — or a usable one — with a plain `Server::builder()`; this is the one that
/// would not, because a cleartext client would then be answered.
#[tokio::test]
async fn a_tls_listener_refuses_a_cleartext_client() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve_on_localhost(Some(&serve_tls(cert.path(), key.path()))).await;

    let outcome = in_cleartext(port).await;
    assert!(
        outcome.is_err(),
        "a listener told to serve TLS must not answer a cleartext client: {outcome:?}"
    );
}

/// The identity SERVED is the one configured, not any certificate that parses.
/// A client trusting a different authority must be refused — which is what an
/// impostor's certificate would look like, and the property that makes
/// verification worth doing at all.
#[tokio::test]
async fn a_client_trusting_another_authority_is_refused() {
    let served = pki(SERVED_NAME);
    let cert = TempPem::with(&served.cert_pem);
    let key = TempPem::with(&served.key_pem);
    let port = serve_on_localhost(Some(&serve_tls(cert.path(), key.path()))).await;

    // A second authority, which issued nothing this listener holds.
    let stranger = pki(SERVED_NAME);
    let outcome = over_tls(port, &stranger.ca_pem).await;
    assert!(
        outcome.is_err(),
        "a certificate from an authority the client does not trust must be refused: {outcome:?}"
    );
}

/// THE DEFAULT, and the property the whole change is built around: nothing
/// configured serves exactly what this service has always served. It also stops
/// the case above from starting to pass because everything became TLS.
#[tokio::test]
async fn an_unconfigured_listener_still_serves_cleartext() {
    let port = serve_on_localhost(None).await;
    assert_eq!(in_cleartext(port).await, Ok(200));
}

/// A path that is not there at all — the mistake an operator actually makes is a
/// mount that did not happen. The answer to it is an error naming the file, and
/// never a plaintext listener.
#[tokio::test]
async fn a_certificate_that_cannot_be_read_refuses_the_boot() {
    let p = pki(SERVED_NAME);
    let key = TempPem::with(&p.key_pem);
    let missing = std::env::temp_dir().join("yadgar-task-no-such-cert-6a19f4.pem");

    let tls = serve_tls(&missing, key.path());
    let error = serve::builder(Some(&tls)).expect_err("a missing certificate must refuse");
    assert!(
        matches!(error, ServeTlsError::Unreadable { .. }),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("yadgar-task-no-such-cert-6a19f4.pem"),
        "the message must name the file that was wrong: {message}"
    );
}

/// The same for the private key, because naming the wrong half of the pair is
/// how an operator spends an afternoon on the wrong mount.
#[tokio::test]
async fn a_private_key_that_cannot_be_read_refuses_the_boot() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let missing = std::env::temp_dir().join("yadgar-task-no-such-key-2f80bd.pem");

    let tls = serve_tls(cert.path(), &missing);
    let error = serve::builder(Some(&tls)).expect_err("a missing private key must refuse");
    assert!(
        matches!(error, ServeTlsError::Unreadable { .. }),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("yadgar-task-no-such-key-2f80bd.pem"),
        "the message must name the file that was wrong: {message}"
    );
}

/// A file that exists and holds no certificate. The PEM readers underneath
/// answer an EMPTY LIST rather than an error, so a bundle that decodes to
/// nothing can look like one that decoded fine — the shape the record says this
/// failure takes.
#[tokio::test]
async fn an_undecodable_certificate_refuses_the_boot() {
    let p = pki(SERVED_NAME);
    let key = TempPem::with(&p.key_pem);

    for contents in ["", "   ", "\n", "there is no certificate in this file\n"] {
        let cert = TempPem::with(contents);
        let tls = serve_tls(cert.path(), key.path());
        let outcome = serve::builder(Some(&tls));
        assert!(
            matches!(outcome, Err(ServeTlsError::Unusable { .. })),
            "a certificate file containing {contents:?} must refuse the boot"
        );
    }
}

/// The same for a key that is not one.
#[tokio::test]
async fn an_undecodable_private_key_refuses_the_boot() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);

    for contents in ["", "   ", "\n", "there is no key in this file\n"] {
        let key = TempPem::with(contents);
        let tls = serve_tls(cert.path(), key.path());
        let outcome = serve::builder(Some(&tls));
        assert!(
            matches!(outcome, Err(ServeTlsError::Unusable { .. })),
            "a key file containing {contents:?} must refuse the boot"
        );
    }
}

/// TWO VALID FILES THAT ARE NOT A PAIR. Both decode, so nothing about reading
/// them fails; the certificate simply does not belong to the key. It is what a
/// half-finished rotation leaves behind, and it must refuse rather than serve.
#[tokio::test]
async fn a_certificate_and_a_key_that_do_not_match_refuse_the_boot() {
    let served = pki(SERVED_NAME);
    let other = pki(SERVED_NAME);
    let cert = TempPem::with(&served.cert_pem);
    let key = TempPem::with(&other.key_pem);

    let tls = serve_tls(cert.path(), key.path());
    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServeTlsError::Unusable { .. })),
        "a certificate that does not belong to the key must refuse the boot: {outcome:?}"
    );
}
