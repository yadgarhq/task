//! The transport this service SERVES on — the other half of [`crate::upstream`].
//!
//! `upstream` decides how this service dials `task-db`; this decides what a
//! caller reaching this service gets. The two are deliberately the same shape —
//! a flag, file paths, a [`ServeTls::from_lookup`] seam and a refusal rather than
//! a downgrade — because one idea written two ways in one repository is its own
//! defect.
//!
//! # TLS
//!
//! **NO COMPILED-IN DEFAULT (ADR-0845).** `LISTEN_TLS_ENABLED` must be exactly
//! "1" or "0"; absent, empty or any other value refuses the boot rather than
//! guessing cleartext. This used to be opt-in — anything but "1" served in
//! cleartext — until ADR-0845 found that an unset variable and a typo both
//! silently meant the same thing. The CUT-OVER ITSELF is still a separate,
//! revertible choice: writing "0" is what reverts it.
//!
//! **Configuration is file paths and a flag, never an issuer-specific resource**
//! (D80). A certificate and a private key on disk are written by cert-manager in
//! the reference deployment and by a hand-assembled Secret anywhere else, and
//! nothing here can tell the difference — which is the point. No CRD, no issuer,
//! no mesh.
//!
//! **A misconfiguration refuses the boot; it never opens a plaintext listener.**
//! That silent downgrade is the entire defect this change exists to remove, so
//! [`builder`] is the ONLY place in this binary that constructs a server: the
//! fallback cannot be reached by forgetting something, only by adding it.
//!
//! **Server TLS only — this is not mutual TLS.** The listener presents an
//! identity and asks the caller for none. The seam for the other direction is
//! tonic's `ServerTlsConfig::client_ca_root` plus one more path, and it is left
//! unbuilt deliberately: every client would need an issued certificate before it
//! could be turned on, which is a decision rather than a line of code.
//!
//! # Shutdown moved to `yadgar-lifecycle`
//!
//! [`yadgar_lifecycle::shutdown`], [`yadgar_lifecycle::DRAIN_BUDGET`] and
//! [`yadgar_lifecycle::drain_within`] were three items in this module, and the
//! same three in `iam` and in `gateway`. They are one decision rather than
//! three: `terminationGracePeriodSeconds` bounds a drain KUBELET started, the
//! rotation watcher ends the serve on its own, so kubelet's clock never runs and
//! a budget this process holds is the only thing bounding what follows.
//!
//! Why they were in a library rather than in `main` is unchanged, and is the
//! same reason [`builder`] is: a decision inside a binary entry point is one no
//! test can reach, and which signals end this process is exactly the kind that
//! fails silently. This binary listened for SIGINT alone while Kubernetes sends
//! SIGTERM.

use std::path::{Path, PathBuf};

use tonic::transport::{Identity, Server, ServerTlsConfig};
// THE ONE ERROR-CHAIN FLATTENER FOR THE ESTATE (ADR-0591). The body that used to
// sit below `builder` in this file was one of five — `iam`, `iam-db`, `task-db`,
// `project-db` and here — byte-identical apart from local names, under TWO
// names: `chain` in the first two and `describe` in the other three. It is
// deleted rather than left beside the shared one, because a consolidation that
// adds a sixth copy without removing the five is worse than none.
use yadgar_telemetry::diagnose::chain;

/// The environment variables this service's own listener is configured from:
/// `LISTEN_TLS_ENABLED`, `LISTEN_TLS_CERT_FILE` and `LISTEN_TLS_KEY_FILE`.
///
/// Built from a PREFIX rather than written out three times, so the naming stays
/// mechanical.
///
/// **THE PREFIX NAMES THE THING BEING CONFIGURED, and it is derived rather than
/// chosen.** `LISTEN` is already the variable holding the address this service
/// binds, so the listener's transport keys extend a name that exists. A dial is
/// named for the upstream it reaches, which is why [`crate::upstream`] reads
/// `TASK_DB_TLS_*`. `SERVE` — what this constant used to be — invented a second
/// word for the listener and so described nothing the process otherwise had, and
/// `iam` derived `LISTEN` independently for the identical seam. One idea spelled
/// two ways across the estate is its own defect.
///
/// A bare `TLS_ENABLED` is ambiguous between the two directions, which is what
/// makes a prefix necessary at all — `the_upstreams_variables_do_not_configure_the_listener`
/// below and `upstream`'s `another_upstreams_variables_do_not_configure_this_one`
/// pin both halves of that.
pub const LISTEN: &str = "LISTEN";

/// What a deployment got wrong about the transport, before anything is bound.
///
/// Every variant is a REFUSAL. There is no variant meaning "carry on in
/// cleartext", because there is no such outcome.
#[derive(Debug, thiserror::Error)]
pub enum ServeTlsError {
    #[error(
        "{0}_TLS_ENABLED must be \"1\" or \"0\" and is {1}. ADR-0845 gives this knob no \
         compiled-in default, so this service cannot guess whether to serve TLS: leaving it \
         unset or empty is refused exactly like any other value outside the two it accepts. \
         Write \"1\" to serve this listener over TLS or \"0\" to serve in cleartext. The chart \
         renders this from `tls.enabled`."
    )]
    EnabledNotBoolean(&'static str, String),

    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_CERT_FILE names no certificate. TLS was \
         asked for, so this is a deployment mistake rather than a reason to open a \
         plaintext listener — and it is NOT the same as leaving TLS off, which is the \
         supported way to serve without one. Point {0}_TLS_CERT_FILE at the PEM \
         certificate this service should present."
    )]
    NoCertFile(&'static str),

    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_KEY_FILE names no private key. A \
         certificate without its key cannot complete a handshake, so this refuses \
         rather than opening a plaintext listener. Point {0}_TLS_KEY_FILE at the PEM \
         private key belonging to {0}_TLS_CERT_FILE."
    )]
    NoKeyFile(&'static str),

    #[error(
        "the TLS {what} at {path} could not be read: {source}. TLS was asked for, so \
         this service refuses to start rather than serving in cleartext. The usual \
         cause is a Secret that was never mounted, or a key inside it under a \
         different name than the chart selected."
    )]
    Unreadable {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "the TLS certificate at {cert} and the private key at {key} were read but \
         refused: {detail}. Both files exist, so this is their CONTENT: a PEM that \
         decodes to no certificate at all, or a certificate that does not belong to \
         the key beside it — what a half-finished rotation leaves behind. This \
         service refuses to start rather than serving in cleartext."
    )]
    Unusable {
        cert: PathBuf,
        key: PathBuf,
        detail: String,
    },
}

/// The identity this service presents: a certificate and its private key, both
/// as paths on disk.
///
/// **No verification domain, unlike [`crate::upstream::UpstreamTls`].** A client
/// checks the name it dialled against the certificate it was shown; a server
/// presents what it was given and checks nothing. The asymmetry is real rather
/// than an omission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeTls {
    cert_file: PathBuf,
    key_file: PathBuf,
}

/// What `*_TLS_ENABLED` looked like, for the refusal naming it — and the
/// reason this takes the RAW, untrimmed lookup result rather than `get`'s
/// output: an absent variable and one set to `""` or whitespace are the same
/// decision today (off would be `"0"`, and neither of these is it), but an
/// operator reading a crash loop needs to tell "I forgot this" from "I set
/// this to nothing" apart, the same distinction `env_required` makes in
/// `main.rs`.
fn describe_enabled(value: Option<&str>) -> String {
    match value.map(str::trim) {
        None => "NOT SET".to_string(),
        Some("") => "\"\" (empty)".to_string(),
        Some(other) => format!("{other:?}"),
    }
}

impl ServeTls {
    /// Read the listener's transport configuration from the environment.
    ///
    /// `Ok(None)` is the explicit-cleartext answer: `{prefix}_TLS_ENABLED` is
    /// "0". There is no unconfigured answer any more (ADR-0845) — absent or
    /// anything else refuses.
    pub fn from_env(prefix: &'static str) -> Result<Option<Self>, ServeTlsError> {
        Self::from_lookup(prefix, |key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between an encrypted listener and a cleartext one
    /// could not be tested at all without this. The same shape
    /// [`crate::upstream::UpstreamTls::from_lookup`] already uses.
    pub fn from_lookup(
        prefix: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, ServeTlsError> {
        let get = |suffix: &str| {
            lookup(&format!("{prefix}_{suffix}"))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        // EXACTLY "1" OR "0", AND NOTHING ELSE — INCLUDING ABSENT (ADR-0845).
        // The knob used to have a compiled-in default: anything but "1" was
        // cleartext, so an unset variable and a typo both silently meant OFF.
        // ADR-0845 deletes that default. A permissive parse here — "false"
        // and "no" both meaning off, or an absent value meaning off — is how
        // a setting meant to be off ends up looking chosen when nobody chose
        // it; the chart renders this variable unconditionally now, so the
        // only way it is genuinely absent is a chart that forgot to.
        //
        // THE RAW LOOKUP, NOT `get`: `get` collapses absent and set-but-empty
        // into the same `None`, which is right for a PATH (nothing to tell
        // apart) and wrong here — `describe_enabled` names the two
        // differently, the same discrimination `env_required` makes in
        // `main.rs` for the knob a nulled chart value actually produces.
        let enabled_raw = lookup(&format!("{prefix}_TLS_ENABLED"));
        match enabled_raw.as_deref().map(str::trim) {
            Some("0") => {
                if get("TLS_CERT_FILE").is_some() || get("TLS_KEY_FILE").is_some() {
                    // NOT an error. Leaving the certificate in place while the
                    // flag is off is exactly how the cut-over gets reverted,
                    // so refusing it would make the lever unusable. It is
                    // still worth a line: a deployment that believes it is
                    // encrypted and is not should be able to see that from
                    // the boot log.
                    tracing::warn!(
                        prefix,
                        "a serving certificate is configured but {prefix}_TLS_ENABLED is \
                         \"0\", so this service listens in CLEARTEXT"
                    );
                }
                return Ok(None);
            }
            Some("1") => {}
            other => {
                return Err(ServeTlsError::EnabledNotBoolean(
                    prefix,
                    describe_enabled(other),
                ))
            }
        }

        Ok(Some(Self {
            cert_file: PathBuf::from(
                get("TLS_CERT_FILE").ok_or(ServeTlsError::NoCertFile(prefix))?,
            ),
            key_file: PathBuf::from(get("TLS_KEY_FILE").ok_or(ServeTlsError::NoKeyFile(prefix))?),
        }))
    }

    /// The PEM certificate this service presents.
    pub fn cert_file(&self) -> &Path {
        &self.cert_file
    }

    /// The PEM private key belonging to that certificate.
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Read both files and hand tonic the pair.
    ///
    /// Reading them HERE rather than letting tonic do it is what lets the error
    /// name WHICH file was wrong. `Identity::from_pem` takes bytes and has no
    /// idea where they came from, so an operator whose Secret mounted only one
    /// of the two would otherwise be told that "an identity" was unusable.
    fn identity(&self) -> Result<Identity, ServeTlsError> {
        let cert = read(&self.cert_file, "certificate")?;
        let key = read(&self.key_file, "private key")?;
        Ok(Identity::from_pem(cert, key))
    }
}

fn read(path: &Path, what: &'static str) -> Result<Vec<u8>, ServeTlsError> {
    // ADR-0523-WATCHED: ServeTls
    std::fs::read(path).map_err(|source| ServeTlsError::Unreadable {
        what,
        path: path.to_path_buf(),
        source,
    })
}

/// Build the gRPC server this service listens with.
///
/// **THE ONLY SERVER CONSTRUCTION IN THIS BINARY, and that is structural rather
/// than stylistic.** The failure this car exists to remove is a listener that
/// opens in cleartext because TLS configuration failed. A `Server::builder()`
/// call anywhere else is a place that downgrade could be written; with one, the
/// only way to reintroduce it is to add a fallback here, where
/// `a_tls_listener_refuses_a_cleartext_client` is looking.
///
/// `None` is the cleartext listener this service has always opened. `Some` is
/// the same server with an identity, and it returns an error rather than a
/// cleartext server if that identity is unusable.
///
/// **ALPN is tonic's, not ours.** `ServerTlsConfig` pushes `h2` onto the
/// acceptor's protocol list, and a gRPC listener that negotiated anything else
/// would answer nothing useful. It is verified rather than assumed: tonic's own
/// client refuses a channel whose negotiated protocol is not `h2`, so the
/// handshake tests in `tests/serve_tls.rs` fail if it ever stops being offered.
pub fn builder(tls: Option<&ServeTls>) -> Result<Server, ServeTlsError> {
    let server = Server::builder();
    let Some(tls) = tls else {
        return Ok(server);
    };

    let identity = tls.identity()?;
    // EAGER, and before anything binds. `tls_config` builds the rustls acceptor
    // here — it is what decodes the PEM and checks that the certificate belongs
    // to the key — so a bad pair is an error at boot rather than a handshake
    // that fails on a stranger's first connection.
    server
        .tls_config(ServerTlsConfig::new().identity(identity))
        .map_err(|e| ServeTlsError::Unusable {
            cert: tls.cert_file.clone(),
            key: tls.key_file.clone(),
            detail: chain(&e),
        })
}

#[cfg(test)]
mod tests;
