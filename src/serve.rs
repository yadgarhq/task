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
//! **OPT-IN, and OFF unless a deployment asks for it.** With nothing configured
//! this serves exactly what it has always served, in cleartext. The code ships
//! first and the cut-over is a separate change that can be reverted on its own.
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

impl ServeTls {
    /// Read the listener's transport configuration from the environment.
    ///
    /// `Ok(None)` is the ordinary answer today: TLS is opt-in, so an
    /// unconfigured deployment serves in cleartext exactly as before.
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

        // Exactly "1". A permissive parse here — "0", "false" and "no" all
        // enabling it — is how a setting meant to be off ends up on, and the
        // reverse mistake is worse: this flag is the revert lever for the
        // cut-over, and a lever that does not move is not one.
        if get("TLS_ENABLED").as_deref() != Some("1") {
            if get("TLS_CERT_FILE").is_some() || get("TLS_KEY_FILE").is_some() {
                // NOT an error. Leaving the certificate in place while the flag
                // is off is exactly how the cut-over gets reverted, so refusing
                // it would make the lever unusable. It is still worth a line: a
                // deployment that believes it is encrypted and is not should be
                // able to see that from the boot log.
                tracing::warn!(
                    prefix,
                    "a serving certificate is configured but {prefix}_TLS_ENABLED is not \
                     \"1\", so this service listens in CLEARTEXT"
                );
            }
            return Ok(None);
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
            detail: describe(&e),
        })
}

/// Flatten an error and everything under it into one sentence.
///
/// `tonic::transport::Error` displays as "transport error" and keeps what
/// actually went wrong in its source — so the message an operator needs is the
/// CHAIN, not the head of it. Losing it is the same class of mistake as printing
/// `Debug` from `main`.
fn describe(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        out.push_str(": ");
        out.push_str(&next.to_string());
        source = next.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SENTINELS: nothing in `serve.rs` could produce either of them, so a test
    /// that sees one saw it travel from the lookup.
    const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/serving.crt";
    const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/serving.key";

    fn lookup<'a>(
        pairs: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// THE DEFAULT, and the property the whole change is built around: nothing
    /// configured means the cleartext listener, unchanged.
    #[test]
    fn nothing_configured_means_no_tls() {
        assert_eq!(ServeTls::from_lookup(LISTEN, lookup(&[])).unwrap(), None);
    }

    /// A certificate without the flag is the REVERTED state, not an error. The
    /// flag is the lever; leaving the paths in place is how it gets pulled back.
    #[test]
    fn a_certificate_alone_does_not_enable_tls() {
        let vars = [
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        assert_eq!(ServeTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
    }

    /// Anything but "1" is off. A permissive parse is how a setting meant to be
    /// off ends up on — and here also how one meant to be revertible stops
    /// being.
    #[test]
    fn only_exactly_one_enables_tls() {
        for value in ["0", "false", "no", "true", "yes", "", " "] {
            let vars = [
                ("LISTEN_TLS_ENABLED", value),
                ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
                ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
            ];
            assert_eq!(
                ServeTls::from_lookup(LISTEN, lookup(&vars)).unwrap(),
                None,
                "{value:?} must not enable TLS"
            );
        }
    }

    /// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no
    /// certificate is a deployment mistake, and the answer to it is an error
    /// rather than a plaintext listener.
    #[test]
    fn asking_for_tls_without_a_certificate_is_an_error() {
        for vars in [
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
            ],
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_CERT_FILE", ""),
                ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
            ],
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_CERT_FILE", "   "),
                ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
            ],
        ] {
            assert!(
                matches!(
                    ServeTls::from_lookup(LISTEN, lookup(&vars)),
                    Err(ServeTlsError::NoCertFile("LISTEN"))
                ),
                "{vars:?} must be refused, not silently downgraded"
            );
        }
    }

    /// The same for the key. Half a pair is not an identity, and the message
    /// has to name the half that is missing.
    #[test]
    fn asking_for_tls_without_a_private_key_is_an_error() {
        for vars in [
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ],
            vec![
                ("LISTEN_TLS_ENABLED", "1"),
                ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
                ("LISTEN_TLS_KEY_FILE", "   "),
            ],
        ] {
            assert!(
                matches!(
                    ServeTls::from_lookup(LISTEN, lookup(&vars)),
                    Err(ServeTlsError::NoKeyFile("LISTEN"))
                ),
                "{vars:?} must be refused, not silently downgraded"
            );
        }
    }

    /// Both paths reach the settings, proved with names the module could not
    /// have chosen for itself.
    #[test]
    fn the_certificate_and_the_key_both_arrive() {
        let vars = [
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        let tls = ServeTls::from_lookup(LISTEN, lookup(&vars))
            .unwrap()
            .expect("a flag, a certificate and a key enable TLS");
        assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
        assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
    }

    /// The prefix is what selects the variables, so the upstream's transport
    /// cannot configure the listener. `TASK_DB_TLS_*` is a real setting in this
    /// process — [`crate::upstream`] reads it — which is what makes this worth
    /// pinning rather than obvious.
    #[test]
    fn the_upstreams_variables_do_not_configure_the_listener() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CERT),
            ("TLS_ENABLED", "1"),
            ("TLS_CERT_FILE", SENTINEL_CERT),
        ];
        assert_eq!(ServeTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
    }
}
