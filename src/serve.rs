//! The transport this service SERVES on — the other half of [`crate::upstream`].
//!
//! `upstream` decides how this service dials `task-db`; this decides what a
//! caller reaching this service gets.
//!
//! # The implementation is `yadgar-lifecycle`'s (B-U5, ADR-0846)
//!
//! This module held its own `ServeTls` until B-U5. Six gRPC servers each held a
//! near-identical copy, and NONE called `client_ca_root`, so no hop verified a
//! client certificate. The one implementation now lives in
//! [`yadgar_lifecycle::serve_tls`], and this module is the WIRING: the prefix
//! this binary reads ([`LISTEN`]) and the chart key it renders from
//! ([`CHART_KEY`]), so every refusal names the variable AND the chart value an
//! operator edits.
//!
//! # TLS and client authentication
//!
//! **NO COMPILED-IN DEFAULT for either switch (ADR-0845, ADR-0854).**
//! `LISTEN_TLS_ENABLED` is exactly "1" or "0" and `LISTEN_TLS_CLIENT_AUTH` is
//! exactly `off`, `optional` or `required`; absent, empty or anything else
//! refuses the boot. `optional` and `required` read the client CA bundle at
//! `LISTEN_TLS_CLIENT_CA_FILE` and verify a presented certificate against it;
//! `required` refuses a caller presenting none. `optional` is a staging step,
//! not a control: anyone can omit a certificate.
//!
//! **Configuration is file paths and a flag, never an issuer-specific resource**
//! (D80). A certificate and a private key on disk are written by cert-manager in
//! the reference deployment and by a hand-assembled Secret anywhere else, and
//! nothing here can tell the difference.
//!
//! **A misconfiguration refuses the boot; it never opens a plaintext listener.**
//! [`builder`] is the ONLY place in this binary that constructs a server, so the
//! fallback cannot be reached by forgetting something, only by adding it.
//!
//! # Shutdown moved to `yadgar-lifecycle`
//!
//! [`yadgar_lifecycle::shutdown`], [`yadgar_lifecycle::DRAIN_BUDGET`] and
//! [`yadgar_lifecycle::drain_within`] were three items in this module, and the
//! same three in `iam` and in `gateway`. They are one decision rather than
//! three: `terminationGracePeriodSeconds` bounds a drain KUBELET started, the
//! rotation watcher ends the serve on its own, so kubelet's clock never runs and
//! a budget this process holds is the only thing bounding what follows.

use tonic::transport::Server;

pub use yadgar_lifecycle::serve_tls::{ClientAuth, ServeTlsError, ServerTls, LISTEN};

/// The chart values block the listener's keys render from: `tls.enabled`,
/// `tls.clientAuth`, `tls.certSecret` and `tls.clientCaSecret` in
/// `chart/values.yaml`. Every refusal names `<CHART_KEY>.<leaf>`, which is the
/// value an operator reading a crash loop edits.
pub const CHART_KEY: &str = "tls";

/// Read the listener's configuration from the process environment.
///
/// `Ok(None)` is the cleartext listener, and only ever the answer to an
/// EXPLICIT `LISTEN_TLS_ENABLED=0` with `LISTEN_TLS_CLIENT_AUTH=off`.
pub fn from_env() -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_env(LISTEN, CHART_KEY)
}

/// The same decision, over an injected lookup.
///
/// **A seam, because environment variables are process-global.** A test that
/// sets one steers every other test running in the same binary.
pub fn from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_lookup(LISTEN, CHART_KEY, lookup)
}

/// Build the gRPC server this service listens with.
///
/// **THE ONLY SERVER CONSTRUCTION IN THIS BINARY.** `None` is the cleartext
/// listener [`from_env`] returned for an explicit `LISTEN_TLS_ENABLED=0`;
/// `Some` is TLS — with the client verifier its mode asks for — or an error,
/// never cleartext. Every file is read and the acceptor built HERE, before
/// anything binds, so a bad mount refuses at boot.
///
/// **ALPN is tonic's, not ours.** `ServerTlsConfig` pushes `h2` onto the
/// acceptor's protocol list; the handshake tests in `tests/serve_tls.rs` fail
/// if it ever stops being offered, because tonic's own client refuses a
/// channel whose negotiated protocol is not `h2`.
pub fn builder(tls: Option<&ServerTls>) -> Result<Server, ServeTlsError> {
    yadgar_lifecycle::serve_tls::server(tls)
}

#[cfg(test)]
mod tests;
