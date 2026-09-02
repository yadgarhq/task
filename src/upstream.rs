//! Connecting to `task-db`, this module's twin.
//!
//! Kept separate from [`yadgar_dial`] deliberately: the crate is the generic
//! channel-balancing mechanism (D23) — it knows about `SocketAddr`s and DNS, and
//! nothing about which module it is balancing for. This is the thin,
//! module-specific wiring on top: `task-db`'s env-configured host, port and
//! transport, named the way `main.rs` expects.
//!
//! # TLS
//!
//! **OPT-IN, and OFF unless a deployment asks for it.** With nothing configured
//! this dials exactly as it always has, in cleartext. That is deliberate rather
//! than timid: the code ships first and the cut-over is a separate change that
//! can be reverted on its own, and no server in the estate serves TLS yet.
//!
//! **Configuration is file paths and a flag, never an issuer-specific resource**
//! (D80). A CA bundle on disk is written by cert-manager in the reference
//! deployment and by a hand-assembled Secret anywhere else, and neither this
//! module nor [`yadgar_dial`] can tell the difference — which is the point.
//!
//! **A misconfiguration is an error, never a downgrade.** Asking for TLS without
//! naming a CA bundle fails here; a bundle that cannot be read, cannot be
//! decoded, or holds no certificate fails inside `yadgar_dial::connect_tls`.
//! `main` surfaces both before the listener binds. Nothing falls back to
//! cleartext, and nothing falls back to the platform trust store.

use std::path::{Path, PathBuf};

use tonic::transport::Channel;

use yadgar_dial::{BalanceError, TlsOptions};

/// The environment variables one upstream's transport is configured from.
///
/// Built from a PREFIX rather than written out three times, so the naming stays
/// mechanical: `<PREFIX>_TLS_ENABLED`, `<PREFIX>_TLS_CA_FILE` and
/// `<PREFIX>_TLS_DOMAIN`. This service has one upstream, `TASK_DB`; the gateway
/// has two, and uses the identical shape for both.
pub const TASK_DB: &str = "TASK_DB";

/// What a deployment got wrong about the transport, before anything is dialled.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_CA_FILE names no CA bundle. TLS was asked \
         for, so this is a deployment mistake rather than a reason to connect in \
         cleartext — and it is NOT the same as leaving TLS off, which is the \
         supported way to run without one. Point {0}_TLS_CA_FILE at the PEM bundle \
         holding the authority that signed the upstream's certificate."
    )]
    NoCaFile(&'static str),
}

/// Server TLS for one upstream: a CA bundle on disk, and optionally the name to
/// verify against.
///
/// **The verification domain defaults to the host being dialled**, which is what
/// [`yadgar_dial`] does with it and the reason a certificate issued for the
/// Service name works while the balancer talks to pod addresses. The override
/// exists for a certificate that names something else — a per-namespace FQDN,
/// say — and is not needed otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamTls {
    ca_file: PathBuf,
    domain: Option<String>,
}

impl UpstreamTls {
    /// Read one upstream's transport configuration from the environment.
    ///
    /// `Ok(None)` is the ordinary answer today: TLS is opt-in, so an
    /// unconfigured deployment dials in cleartext exactly as before.
    pub fn from_env(prefix: &'static str) -> Result<Option<Self>, TlsConfigError> {
        Self::from_lookup(prefix, |key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between an encrypted transport and a cleartext one
    /// could not be tested at all without this. Copied in shape from the
    /// gateway's `Attestation::from_lookup`, which exists for the same reason.
    pub fn from_lookup(
        prefix: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, TlsConfigError> {
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
            if get("TLS_CA_FILE").is_some() {
                // NOT an error. Leaving the bundle in place while the flag is
                // off is exactly how the cut-over gets reverted, so refusing it
                // would make the lever unusable. It is still worth a line: a
                // deployment that believes it is encrypted and is not should be
                // able to see that from the boot log.
                tracing::warn!(
                    prefix,
                    "a CA bundle is configured but {prefix}_TLS_ENABLED is not \"1\", so this \
                     upstream is dialled in CLEARTEXT"
                );
            }
            return Ok(None);
        }

        Ok(Some(Self {
            ca_file: PathBuf::from(get("TLS_CA_FILE").ok_or(TlsConfigError::NoCaFile(prefix))?),
            domain: get("TLS_DOMAIN"),
        }))
    }

    /// The PEM bundle holding the authorities this upstream is verified against.
    pub fn ca_file(&self) -> &Path {
        &self.ca_file
    }

    /// The name the peer's certificate is checked against, when it is not the
    /// host being dialled.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// The same settings as [`yadgar_dial`] takes them.
    pub fn options(&self) -> TlsOptions {
        let options = TlsOptions::new(&self.ca_file);
        match &self.domain {
            None => options,
            Some(domain) => options.domain_name(domain),
        }
    }
}

/// Connect to `task-db` and return a load-balanced [`Channel`].
///
/// `task-db`'s Service is headless (D23), so this goes through `yadgar_dial` —
/// one long-lived HTTP/2 connection per pod, re-resolved every 5s — rather than
/// a plain single-endpoint `Endpoint::connect`.
///
/// **`tls` decides the transport, and there is no third state.** `None` is the
/// cleartext path this service has always taken; `Some` is the same balancing
/// with the connection encrypted and the peer verified, and it returns an error
/// rather than a cleartext channel if the bundle is unusable.
pub async fn connect(
    host: &str,
    port: u16,
    tls: Option<&UpstreamTls>,
) -> Result<Channel, BalanceError> {
    match tls {
        None => yadgar_dial::connect(host, port).await,
        Some(tls) => yadgar_dial::connect_tls(host, port, &tls.options()).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values below are SENTINELS: nothing in `upstream.rs` could produce
    /// either of them, so a test that sees one saw it travel from the lookup.
    const SENTINEL_CA: &str = "/etc/yadgar/aardvark-9f3c/bundle.pem";
    const SENTINEL_DOMAIN: &str = "task-db.verified-as-this.invalid";

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
    /// configured means the cleartext path, unchanged.
    #[test]
    fn nothing_configured_means_no_tls() {
        assert_eq!(
            UpstreamTls::from_lookup(TASK_DB, lookup(&[])).unwrap(),
            None
        );
    }

    /// A bundle without the flag is the REVERTED state, not an error. The flag
    /// is the lever; leaving the path in place is how it gets pulled back.
    #[test]
    fn a_ca_bundle_alone_does_not_enable_tls() {
        let vars = [("TASK_DB_TLS_CA_FILE", SENTINEL_CA)];
        assert_eq!(
            UpstreamTls::from_lookup(TASK_DB, lookup(&vars)).unwrap(),
            None
        );
    }

    /// Anything but "1" is off. A permissive parse is how a setting meant to be
    /// off ends up on — and here also how one meant to be revertible stops
    /// being.
    #[test]
    fn only_exactly_one_enables_tls() {
        for value in ["0", "false", "no", "true", "yes", "", " "] {
            let vars = [
                ("TASK_DB_TLS_ENABLED", value),
                ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
            ];
            assert_eq!(
                UpstreamTls::from_lookup(TASK_DB, lookup(&vars)).unwrap(),
                None,
                "{value:?} must not enable TLS"
            );
        }
    }

    /// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no bundle
    /// is a deployment mistake, and the answer to it is an error rather than a
    /// cleartext channel or the platform trust store.
    #[test]
    fn asking_for_tls_without_a_ca_bundle_is_an_error() {
        for vars in [
            vec![("TASK_DB_TLS_ENABLED", "1")],
            vec![("TASK_DB_TLS_ENABLED", "1"), ("TASK_DB_TLS_CA_FILE", "")],
            vec![("TASK_DB_TLS_ENABLED", "1"), ("TASK_DB_TLS_CA_FILE", "   ")],
        ] {
            assert!(
                matches!(
                    UpstreamTls::from_lookup(TASK_DB, lookup(&vars)),
                    Err(TlsConfigError::NoCaFile("TASK_DB"))
                ),
                "{vars:?} must be refused, not silently downgraded"
            );
        }
    }

    /// Both values reach the settings, proved with names the module could not
    /// have chosen for itself.
    #[test]
    fn the_bundle_and_the_domain_both_arrive() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
            ("TASK_DB_TLS_DOMAIN", SENTINEL_DOMAIN),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.ca_file(), Path::new(SENTINEL_CA));
        assert_eq!(tls.domain(), Some(SENTINEL_DOMAIN));
    }

    /// The domain is OPTIONAL, and its absence means "verify against the host",
    /// which is `yadgar_dial`'s own default rather than a value invented here.
    #[test]
    fn the_domain_is_optional() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.domain(), None);
    }

    /// A host that resolves to nothing, so the only thing either dial can
    /// report is WHICH dial it was.
    const UNRESOLVABLE: &str = "task-db-no-such-host-4b7e02.invalid";

    /// THE ARGUMENT IS NOT DECORATION. A `connect` that accepted `Some(tls)`
    /// and called `yadgar_dial::connect` anyway would pass every test above —
    /// they only inspect the configuration — and would ship a cleartext dial
    /// wearing a TLS configuration.
    ///
    /// `yadgar_dial::connect_tls` checks the CA bundle BEFORE it resolves the
    /// host, and `connect` does not check bundles at all. So a bundle that does
    /// not exist, against a host that does not resolve, tells the two apart:
    /// only the TLS path can answer `CaUnreadable`. Drop the `Some` arm and this
    /// reports `Dns` instead.
    #[tokio::test]
    async fn a_tls_dial_goes_through_connect_tls_and_not_through_connect() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .unwrap();

        assert!(
            matches!(
                connect(UNRESOLVABLE, 50051, Some(&tls)).await,
                Err(BalanceError::CaUnreadable { .. })
            ),
            "a TLS dial must read the bundle, which only connect_tls does"
        );
    }

    /// The other direction, so the case above cannot start passing because
    /// everything became TLS. A cleartext dial reads no bundle and fails on the
    /// name, which is the behaviour this service has always had.
    #[tokio::test]
    async fn a_cleartext_dial_reads_no_bundle() {
        assert!(
            matches!(
                connect(UNRESOLVABLE, 50051, None).await,
                Err(BalanceError::Dns { .. })
            ),
            "a cleartext dial must go straight to the resolver"
        );
    }

    /// The prefix is what selects the variables, so a value meant for another
    /// upstream cannot configure this one. Cheap here, load-bearing in the
    /// gateway, which reads two prefixes in one process.
    #[test]
    fn another_upstreams_variables_do_not_configure_this_one() {
        let vars = [
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
            ("TLS_ENABLED", "1"),
        ];
        assert_eq!(
            UpstreamTls::from_lookup(TASK_DB, lookup(&vars)).unwrap(),
            None
        );
    }
}
