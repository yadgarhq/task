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
//! # Mutual TLS
//!
//! **The transport above is one direction; this is the other.** The CA bundle
//! authenticates the upstream to this service. A client certificate
//! authenticates THIS SERVICE to the upstream — ADR-0516, which chose mutual TLS
//! over a NetworkPolicy because a control the CNI enforces protects an EKS
//! deployment and protects nothing on kind (D80).
//!
//! **A SEPARATE LEVER FROM THE ENCRYPTED TRANSPORT, deliberately.**
//! `<PREFIX>_TLS_CLIENT_CERT_FILE` and `<PREFIX>_TLS_CLIENT_KEY_FILE` are unset
//! by default, so a deployment that turns TLS on verifies the upstream and
//! presents no identity — exactly as it did before. Mutual TLS is then its own
//! change, revertible on its own, which is what car 1's discipline asks for.
//!
//! **AND IT IS A DIFFERENT CERTIFICATE FROM THE ONE THIS SERVICE SERVES.** The
//! serving leaf is issued for `server auth`, the client leaf for `client auth`,
//! and a peer that trusts the issuer still refuses a leaf naming the wrong
//! purpose. One authority issues both.
//!
//! **THE CLIENT CERTIFICATE IS LOAD-BEARING FOR AVAILABILITY**, which the
//! serving one is not in the same way. ADR-0516 says it plainly: an expired
//! client certificate STOPS this hop rather than weakening it. That is why both
//! files join [`crate::rotate`]'s watch set in the same change that mounts them
//! — a process that reads them once and never again works perfectly until the
//! leaf expires, and then fails hard with nothing having warned.
//!
//! **NOTHING HERE CHECKS WHAT THE CERTIFICATE SAYS THE CALLER IS.** The upstream
//! learns that this deployment issued the leaf, not which service presented it.
//! Distinguishing callers needs a check against the name in the certificate, and
//! no such check exists in this estate today.
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
/// Built from a PREFIX rather than written out five times, so the naming stays
/// mechanical: `<PREFIX>_TLS_ENABLED`, `<PREFIX>_TLS_CA_FILE`, `<PREFIX>_TLS_DOMAIN`,
/// `<PREFIX>_TLS_CLIENT_CERT_FILE` and `<PREFIX>_TLS_CLIENT_KEY_FILE`. This service has one upstream, `TASK_DB`; the gateway
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

    #[error(
        "{0}_TLS_CLIENT_CERT_FILE names a client certificate but {0}_TLS_CLIENT_KEY_FILE \
         names no private key. A certificate cannot be presented without the key that \
         proves it, so this is a deployment mistake rather than a reason to dial with no \
         identity at all — dialling without one is what leaving BOTH unset means, and it \
         is the default. Point {0}_TLS_CLIENT_KEY_FILE at the private key belonging to \
         that certificate."
    )]
    ClientCertificateWithoutKey(&'static str),

    #[error(
        "{0}_TLS_CLIENT_KEY_FILE names a private key but {0}_TLS_CLIENT_CERT_FILE names no \
         certificate. A key proves a certificate and is worth nothing on its own, so this \
         is a deployment mistake rather than a reason to dial with no identity at all — \
         dialling without one is what leaving BOTH unset means, and it is the default. \
         Point {0}_TLS_CLIENT_CERT_FILE at the certificate that key belongs to."
    )]
    ClientKeyWithoutCertificate(&'static str),
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
    client: Option<ClientIdentity>,
}

/// The certificate this service PRESENTS to the upstream, and the private key
/// that proves it — mutual TLS (ADR-0516).
///
/// **A DIFFERENT CERTIFICATE FROM THE ONE THIS SERVICE SERVES, and confusing the
/// two is not an error anybody sees at build time.** A serving leaf is issued for
/// `server auth` and a client leaf for `client auth`; a peer verifying a client
/// chain refuses a leaf that names the wrong purpose even though it trusts the
/// issuer perfectly well. That separation is what lets one authority issue both.
///
/// **The two paths live together rather than as two `Option`s**, the same shape
/// `yadgar_dial::TlsOptions` uses: one without the other is not a configuration,
/// it is a mistake, and it is caught in [`UpstreamTls::from_lookup`] rather than
/// at the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientIdentity {
    certificate: PathBuf,
    key: PathBuf,
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
            // THE CLIENT CERTIFICATE IS NAMED HERE TOO, and leaving it out was
            // the silent case: an operator who mounts a client leaf and forgets
            // the flag gets a cleartext hop presenting no identity, and nothing
            // says so. Mutual TLS is meaningless without the encrypted transport
            // it runs inside, so this one flag turns both off.
            if get("TLS_CA_FILE").is_some() || get("TLS_CLIENT_CERT_FILE").is_some() {
                // NOT an error. Leaving the bundle in place while the flag is
                // off is exactly how the cut-over gets reverted, so refusing it
                // would make the lever unusable. It is still worth a line: a
                // deployment that believes it is encrypted and is not should be
                // able to see that from the boot log.
                tracing::warn!(
                    prefix,
                    "a CA bundle or a client certificate is configured but \
                     {prefix}_TLS_ENABLED is not \"1\", so this upstream is dialled in \
                     CLEARTEXT and presents no identity"
                );
            }
            return Ok(None);
        }

        // BOTH, OR NEITHER. A certificate with no key cannot be presented and a
        // key with no certificate proves nothing, so each half alone is a
        // deployment mistake — and it is refused here rather than left to fail
        // at a handshake, where the message names neither variable.
        let client = match (get("TLS_CLIENT_CERT_FILE"), get("TLS_CLIENT_KEY_FILE")) {
            (None, None) => None,
            (Some(certificate), Some(key)) => Some(ClientIdentity {
                certificate: PathBuf::from(certificate),
                key: PathBuf::from(key),
            }),
            (Some(_), None) => return Err(TlsConfigError::ClientCertificateWithoutKey(prefix)),
            (None, Some(_)) => return Err(TlsConfigError::ClientKeyWithoutCertificate(prefix)),
        };

        Ok(Some(Self {
            ca_file: PathBuf::from(get("TLS_CA_FILE").ok_or(TlsConfigError::NoCaFile(prefix))?),
            domain: get("TLS_DOMAIN"),
            client,
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

    /// The certificate this service presents to the upstream, when it presents
    /// one.
    ///
    /// **`None` is the default and is not a degraded state**: mutual TLS is a
    /// separate lever from the encrypted transport, so a deployment can verify
    /// the upstream without identifying itself to it.
    pub fn client_certificate_file(&self) -> Option<&Path> {
        self.client.as_ref().map(|c| c.certificate.as_path())
    }

    /// The private key belonging to that certificate. Present exactly when
    /// [`Self::client_certificate_file`] is.
    pub fn client_key_file(&self) -> Option<&Path> {
        self.client.as_ref().map(|c| c.key.as_path())
    }

    /// The same settings as [`yadgar_dial`] takes them.
    ///
    /// **The client identity travels with them when one is configured**, so
    /// there is no second call a caller can forget to make: whatever a
    /// deployment stated about this upstream is in the value handed to
    /// `connect_tls`, identity included.
    pub fn options(&self) -> TlsOptions {
        let options = TlsOptions::new(&self.ca_file);
        let options = match &self.domain {
            None => options,
            Some(domain) => options.domain_name(domain),
        };
        match &self.client {
            None => options,
            Some(client) => options.identity(&client.certificate, &client.key),
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
    const SENTINEL_CLIENT_CERT: &str = "/etc/yadgar/aardvark-9f3c/task-caller.pem";
    const SENTINEL_CLIENT_KEY: &str = "/etc/yadgar/aardvark-9f3c/task-caller-key.pem";
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
    /// `yadgar_dial::connect_tls` checks the CA bundle BEFORE it dials the
    /// host, and `connect` does not check bundles at all. So a bundle that does
    /// not exist, against a host that does not resolve, tells the two apart:
    /// only the TLS path can answer `CaUnreadable`. Drop the `Some` arm and
    /// this returns `Ok`.
    ///
    /// **THAT LAST SENTENCE USED TO SAY `Dns`, and the pin move to `dial`
    /// v0.2.0 is what changed it.** A cleartext dial at a name that does not
    /// resolve is no longer an error at all (ADR-0532), so the cleartext arm
    /// answers `Ok` rather than a different error. The discrimination survives
    /// — an unusable bundle is still refused before a channel exists — and
    /// `a_cleartext_dial_reads_no_bundle` below asserts the two answers against
    /// each other rather than each against a constant.
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
    /// everything became TLS.
    ///
    /// **AN ABSENT `task-db` IS NO LONGER A FAILED DIAL, and this case is
    /// where the pin move to `dial` v0.2.0 announced itself.** It asserted
    /// `BalanceError::Dns` and went RED on the bump. ADR-0532 made the boot dial
    /// lazy: a name with no Service behind it yet is seeded into the balancer
    /// and dialled, so `connect` hands back a channel and the failure moves to
    /// the request. `Dns` and `DnsTimedOut` remain `BalanceError` variants, and
    /// as far as this repository can tell no public entry point of that crate
    /// returns either one now: `resolve` is private, `connect_with` warns and
    /// continues with an empty set, and the refresh loop reports through
    /// `still_absent` and continues. Nothing here tests that claim about
    /// another crate's internals, so it is written as a reading rather than a
    /// property.
    ///
    /// **THIS IS A DIFFERENTIAL PAIR, not two assertions against constants.**
    /// Each `assert!` below IS against a constant — that is unavoidable and not
    /// the point. What the case buys is that the two calls differ in ONE thing,
    /// the `tls` argument: same host, same port, same function. So a `connect`
    /// that ignored that argument could not pass both, which is the mutant
    /// `is_ok()` on its own would let through.
    #[tokio::test]
    async fn a_cleartext_dial_reads_no_bundle() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .unwrap();

        let cleartext = connect(UNRESOLVABLE, 50051, None).await;
        let encrypted = connect(UNRESOLVABLE, 50051, Some(&tls)).await;

        assert!(
            cleartext.is_ok(),
            "a name that does not resolve must not fail the dial: {:?}",
            cleartext.err()
        );
        assert!(
            matches!(encrypted, Err(BalanceError::CaUnreadable { .. })),
            "the same host with a bundle must still read it: {encrypted:?}"
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

    /// THE DEFAULT: no client certificate, so the dial presents no identity and
    /// behaves exactly as it did before ADR-0516.
    #[test]
    fn no_client_certificate_is_the_default() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.client_certificate_file(), None);
        assert_eq!(tls.client_key_file(), None);
    }

    /// BOTH PATHS ARRIVE, proved with names the module could not have chosen for
    /// itself. This is what `UpstreamTls`'s `Material` implementation reads to
    /// put them in the watch set, so a value that stopped travelling here would
    /// silently empty half the set.
    #[test]
    fn the_client_certificate_and_its_key_both_arrive() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
            ("TASK_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
            ("TASK_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(
            tls.client_certificate_file(),
            Some(Path::new(SENTINEL_CLIENT_CERT))
        );
        assert_eq!(tls.client_key_file(), Some(Path::new(SENTINEL_CLIENT_KEY)));
    }

    /// HALF AN IDENTITY IS A DEPLOYMENT MISTAKE, refused at boot naming the
    /// variable rather than at a handshake naming neither. A certificate cannot
    /// be presented without its key, and a key on its own proves nothing.
    #[test]
    fn half_a_client_identity_is_refused() {
        let cert_only = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
            ("TASK_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
        ];
        assert!(matches!(
            UpstreamTls::from_lookup(TASK_DB, lookup(&cert_only)),
            Err(TlsConfigError::ClientCertificateWithoutKey(TASK_DB))
        ));

        let key_only = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
            ("TASK_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
        ];
        assert!(matches!(
            UpstreamTls::from_lookup(TASK_DB, lookup(&key_only)),
            Err(TlsConfigError::ClientKeyWithoutCertificate(TASK_DB))
        ));
    }

    /// AN EMPTY VALUE IS AN UNSET ONE, the same rule the CA bundle already gets.
    /// A values override that nulls the Secret name renders an empty string, and
    /// treating that as a configured path would fail the boot over a deployment
    /// that simply asked for no identity.
    #[test]
    fn an_empty_client_path_is_the_same_as_an_unset_one() {
        let vars = [
            ("TASK_DB_TLS_ENABLED", "1"),
            ("TASK_DB_TLS_CA_FILE", SENTINEL_CA),
            ("TASK_DB_TLS_CLIENT_CERT_FILE", "  "),
            ("TASK_DB_TLS_CLIENT_KEY_FILE", ""),
        ];
        let tls = UpstreamTls::from_lookup(TASK_DB, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.client_certificate_file(), None);
    }

    /// A CLIENT CERTIFICATE WITHOUT THE FLAG IS THE REVERTED STATE, not an
    /// error. Mutual TLS runs inside the encrypted transport, so the one flag
    /// turns both off, and leaving the paths in place is how the cut-over gets
    /// pulled back.
    #[test]
    fn a_client_certificate_alone_does_not_enable_tls() {
        let vars = [
            ("TASK_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
            ("TASK_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
        ];
        assert_eq!(
            UpstreamTls::from_lookup(TASK_DB, lookup(&vars)).unwrap(),
            None
        );
    }

    /// The gauge `dial` publishes for an upstream that never resolved reaches
    /// this binary's registry, under the name and the label an alert queries.
    ///
    /// **A METRIC A LIBRARY EMITS IS NOT AUTOMATICALLY A SERIES THIS SERVICE
    /// EXPORTS, and this case is what makes the difference visible.** On `dial`
    /// v0.2.0 the key does not exist at all, so this went RED before the pin
    /// moved. What it proves once green is the whole chain: the emission is on
    /// the boot path this service actually calls, it goes through the `metrics`
    /// facade this binary links rather than a second one, and
    /// `yadgar_telemetry::metrics::install_prometheus` builds a
    /// `PrometheusBuilder` with no allow-list, so a gauge in the registry is a
    /// gauge on `/metrics`.
    ///
    /// **THE NAME IS ASSERTED AS A STRING LITERAL, NOT AS
    /// `yadgar_dial::UPSTREAM_NEVER_RESOLVED`.** Comparing that constant with
    /// itself passes through a rename, and a rename is the one change to a
    /// metric that fails nowhere: every consumer compiles, a dashboard blanks
    /// and an alert stops. Spelling it out makes the next pin move that renames
    /// it fail HERE instead.
    ///
    /// **THERE IS NO `service` LABEL ON THIS SERIES.** `dial` is a library
    /// dialling outward with no service identity of its own and documents that
    /// it writes no second label, and `install_prometheus` adds no global one.
    /// `upstream` is the only dimension; the pod and the job come from the
    /// scrape. It differs from `yadgar_rotation_watched_files_unreadable` for
    /// that reason, not by oversight.
    #[test]
    fn an_absent_task_db_is_published_as_a_gauge() {
        let (emitted, _channel) = dial_under_a_recorder(UNRESOLVABLE);
        assert!(
            gauge_for(&emitted, UNRESOLVABLE, 1.0),
            "a task-db that never resolved must be published as a gauge an \
             alert can read: {emitted:?}"
        );
    }

    /// The other direction, and it is not symmetry for its own sake.
    ///
    /// **A GAUGE WRITTEN ONLY ON THE UNHEALTHY PATH DOES NOT EXIST ON A HEALTHY
    /// POD**, and a series that does not exist cannot be compared against zero:
    /// `> 0` matches nothing, so "healthy" reads the same as "this crate was
    /// never linked" and the same as "the process died before its first tick".
    /// The boot dial publishing BOTH ways is what the alert `> 0` depends on,
    /// and it is a property of the pin rather than of this repository — so it is
    /// asserted here, where the pin is.
    #[test]
    fn a_task_db_that_resolves_publishes_the_same_gauge_at_zero() {
        let (emitted, _channel) = dial_under_a_recorder(RESOLVABLE);
        assert!(
            gauge_for(&emitted, RESOLVABLE, 0.0),
            "a resolvable task-db must still publish the series, at zero: \
             {emitted:?}"
        );
    }

    /// One row of a [`metrics_util::debugging::Snapshotter`] snapshot: the key
    /// with its kind, the unit and description a `describe_*` would have set,
    /// and the value.
    type Emitted = (
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        metrics_util::debugging::DebugValue,
    );

    /// A name every host resolves without a network: `dial` only needs an
    /// address to build an endpoint, and nothing here connects.
    const RESOLVABLE: &str = "localhost";

    /// Dial `host` with a LOCAL recorder and return everything it emitted.
    ///
    /// Local rather than `metrics::set_global_recorder`: a global one is
    /// process-wide and this binary runs its tests in parallel, so installing
    /// here would race every other case that emits a metric.
    ///
    /// The channel comes back with the snapshot and the caller HOLDS IT.
    /// `dial`'s refresh loop writes this same gauge back to 0 on the way out,
    /// and it leaves when the channel is dropped.
    fn dial_under_a_recorder(host: &str) -> (Vec<Emitted>, tonic::transport::Channel) {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let channel = metrics::with_local_recorder(&recorder, || {
            rt.block_on(async { connect(host, 50051, None).await })
        })
        .expect("a cleartext dial is lazy and hands back a channel");

        // ONE SNAPSHOT. `Snapshotter::snapshot` DRAINS the registry, so a second
        // call sees nothing and its assertion fails while the gauge is being
        // emitted perfectly well.
        let emitted = snapshotter.snapshot().into_vec();
        // LENGTH FIRST, AND IT IS NOT A FORMALITY. A `metrics-util` resolving
        // against another `metrics` major links a SECOND facade; then this
        // snapshot is empty, and every assertion built on it passes vacuously.
        assert!(
            !emitted.is_empty(),
            "the recorder saw no metric at all, which is what a second metrics \
             facade in the tree looks like"
        );
        (emitted, channel)
    }

    /// Is the gauge present for `upstream`, holding `want`?
    fn gauge_for(emitted: &[Emitted], upstream: &str, want: f64) -> bool {
        emitted.iter().any(|(key, _, _, value)| {
            key.key().name() == "yadgar_dial_upstream_never_resolved"
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == "upstream" && l.value() == upstream)
                && matches!(value, metrics_util::debugging::DebugValue::Gauge(g) if g.0 == want)
        })
    }
}
