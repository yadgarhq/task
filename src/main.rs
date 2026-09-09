//! Wiring, and one decision worth naming: this service does NOT wait for
//! `task-db` to be reachable before reporting ready.
//!
//! **THAT SENTENCE WAS FALSE UNTIL `dial` v0.2.0, and the pin move is what made
//! it true.** The twin's own boot is gated — probe, migrate, then listen (D69) —
//! so a `-db` that is not ready has no DNS endpoint behind the headless Service;
//! `yadgar_dial::connect` returned `BalanceError::Dns` for that — CoreDNS
//! answers NXDOMAIN for a headless Service with no ready endpoint, and
//! `connect_with` propagated the resolver's error before it ever reached the
//! empty-answer branch — and the `?` on the dial below turned it into a failed
//! boot. So the cascading outage this
//! paragraph exists to reject is exactly what a `task-db` that had not finished
//! migrating produced. ADR-0532 made the boot dial lazy: the name is seeded into
//! the balancer and dialled until an address answers, `connect` returns a
//! channel, and the failure moves to the request — which is what the rest of
//! this paragraph always assumed. Blocking this service's startup on the twin
//! would turn one module's slow migration into a cascading outage across
//! everything that depends on it, and under D68 a pod stuck in startup is one
//! the autoscaler cannot help. Failing a request with UNAVAILABLE is
//! recoverable; refusing to start is not.
//!
//! **WHAT IT COSTS, stated rather than left to be found.** The readiness probe
//! is a `tcpSocket` on the gRPC port, so this pod reports Ready as soon as it is
//! listening. With `task-db` absent that is a pod that is Ready and answers
//! UNAVAILABLE to EVERY RPC it serves, because this service is a facade over its
//! twin and holds no state of its own. That is a larger share of the surface
//! than the gateway loses when one of its two upstreams goes, and it is said
//! here rather than smoothed over: the ruling above is still the right one, and
//! the cost of it is total. The probe is deliberately NOT changed to
//! gate on the upstream, and the reason is D69's own scope rather than a
//! preference. **D69's boot-failure rule is about a capability of an engine the
//! module OWNS** — it is why the sequence it names is probe, migrate, then
//! listen, and why the twin is where that sequence lives. This service owns no
//! engine and has nothing to migrate, so the only thing it COULD gate on is an
//! RPC asking the twin whether the twin is up. That is inference by proxy, which
//! D69's first rule refuses by name, and a readiness built on it is the cascade
//! this paragraph rejects, moved one layer up.
//!
//! **The discriminator that generalises is whether a RESTART could change the
//! outcome.** A CA bundle that is unreadable, a client certificate that is not
//! mounted, a host that is not a URI authority: a permanent gap, identical after
//! a restart, so fail boot. An upstream that has not appeared yet: transient,
//! and a restart only costs backoff, so dial lazily and fail the request.
//!
//! What makes the absent state visible instead is `yadgar_dial`'s refresh loop,
//! which logs at ERROR on every tick while a host has NEVER resolved —
//! distinctly from the warning a blip gets. **That line reaches `kubectl logs`
//! and nothing else today**: `dial` exports no metric for the never-resolved
//! state, no chart here ships a `PrometheusRule`, and nothing shipping logs off
//! the node. So the signal exists and is not yet alertable, which is the part of
//! the crash loop this change genuinely removes.
//!
//! **The TRANSPORT is a different rule again, in BOTH directions, and it fails
//! boot.** A CA bundle or a serving certificate that is missing, undecodable or
//! mismatched is a deployment mistake rather than an outage, so D69's rule
//! applies and the process refuses to start — the same treatment
//! `YADGAR_MAX_REPLICAS` and `YADGAR_RATE_LIMITS` already get in the gateway.
//! Dialling or listening in cleartext instead is the silent downgrade this whole
//! change exists to remove, so there is no path here that does it.

use yadgar_task::rotate;
use yadgar_task::serve::{self, ServeTls, LISTEN};
use yadgar_task::upstream::{self, UpstreamTls, TASK_DB};

/// Boot steps that would not fit here: see the module's own note on why a
/// binary-only module rather than more of this file.
mod boot;

/// One configuration knob, read from its ONE source, with no compiled-in
/// default behind it (ADR-0569).
///
/// This replaced `env_or(key, default)`, and the deletion is the point rather
/// than the rename: while the helper took a `default` argument, every knob in
/// this binary had somewhere for a fallback to live, and a fallback is invisible
/// at the point of use, survives an upgrade unnoticed, and makes the effective
/// setting depend on which layer a reader happens to inspect.
///
/// AN EMPTY VALUE REFUSES TOO, and with its own message. A set-but-empty
/// variable and an absent one collapsing into a single branch is a defect this
/// estate found three separate times in one week: Helm renders an unset value as
/// `""`, so the empty case is what a nulled chart value actually produces, and it
/// is the one an operator is most likely to hit. This repository has no
/// exception to the rule: every knob `task` reads is required, and none of them
/// treats an empty value as a declared state.
fn env_required(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(format!(
            "{key} is set but EMPTY. It has no compiled-in default (ADR-0569), so there is \
             nothing to fall back to. The chart renders it; a values override that nulls it \
             produces exactly this."
        )),
        Err(_) => Err(format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569): this process reads \
             it from the environment alone and refuses to start rather than invent a value. \
             The chart renders it."
        )),
    }
}

/// The `task-db` boot refusal, flattened through the estate's one error-chain
/// walker (ledger 733, ledger 740, ADR-0591) instead of a second copy.
///
/// **THE ONLY `to_string()` SITE IN THIS FILE THAT TAKES IT.** Every other
/// refusal here — `ServeTls`, `UpstreamTls`, `rotate::Configuration` — already
/// returns a complete sentence with nothing further under it worth a walk.
/// `upstream::connect` is different: it returns `yadgar_dial::BalanceError`,
/// and `BalanceError::Tls` wraps a `tonic::transport::Error` whose entire
/// `Display` is the two words `transport error` — measured, this is the one
/// place in this file where the head of the chain is a dead end and the reason
/// sits one `source()` hop below it. `gateway#44` measured the same signature
/// at its own two call sites and took the walk there for the identical reason;
/// this is the same class, ledger 740, reaching the two repositories `gateway`
/// does not dial.
///
/// **NOT A SECOND FLATTENER.** The body is a call to
/// `yadgar_telemetry::diagnose::chain` and nothing else. It exists as a named
/// function only because `main` is a binary target: every `map_err` closure
/// inside it is unreachable from a test, so routing this one call through a
/// seam is what gives the property somewhere to be asserted. Reverting this
/// body to `error.to_string()` turns
/// `a_refusal_carries_the_layer_below_transport_error` red.
///
/// **THE DUPLICATION `gateway#44` ACCEPTED APPLIES HERE UNCHANGED.**
/// `BalanceError` has ten variants, six of which carry `#[source]` — and all
/// six also interpolate `{source}` into their own `#[error]` string, `Tls`
/// included. So the walk appends a duplicate tail on every one of them: a CA
/// bundle that cannot be read renders `... (os error 2). TLS was requested \
/// ...: No such file or directory (os error 2)`. That is a known defect
/// (ledger 737, tracked in `yadgar-dial`, not fixed here) and is accepted as
/// the cost of reaching the one layer this file would otherwise lose.
fn refusal(error: &dyn std::error::Error) -> String {
    yadgar_telemetry::diagnose::chain(error)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    boot::install_logging();

    // FIRST, before a socket of any kind is opened. The identity this service
    // presents is read and CHECKED here — the PEM decoded, the certificate
    // matched against its key — so a deployment that asked for TLS and got the
    // mount wrong exits now rather than after something is already listening.
    //
    // `serve::builder` is the only server construction in this binary, which is
    // structural rather than tidy: the downgrade this car removes is a listener
    // that opens in cleartext because TLS configuration failed, and with one
    // construction site there is nowhere else to write it.
    let tls = ServeTls::from_env(LISTEN).map_err(|e| e.to_string())?;
    let server = serve::builder(tls.as_ref()).map_err(|e| e.to_string())?;

    // The HEADLESS Service name (D23). Resolving it yields every ready pod
    // address rather than one virtual IP.
    let db_host = env_required("TASK_DB_HOST")?;
    // STRINGIFIED AND NAMED, for the same reason as every other error in this
    // function: `main` returns `Box<dyn Error>`, which Rust prints with DEBUG. A
    // bare `?` here yields `ParseIntError { kind: InvalidDigit }`, and the two
    // addresses below yield `AddrParseError(())` — a CrashLoop whose entire
    // output is `AddrParseError(())` tells an operator neither which variable was
    // wrong nor what it held. These three were the last bare `?`s left beside the
    // comments explaining why nothing else is one.
    let db_port: u16 = env_required("TASK_DB_PORT")?
        .parse()
        .map_err(|e| format!("TASK_DB_PORT is not a port number: {e}"))?;

    // OPT-IN, and OFF unless a deployment asks for it. Nothing configured means
    // the cleartext dial this service has always done — no server in the estate
    // serves TLS yet, so the cut-over is a later change that can be reverted on
    // its own.
    //
    // `.to_string()` on the way out, and not decoration: `main` returns
    // `Box<dyn Error>`, which Rust prints with DEBUG — so a bare `?` would put
    // `NoCaFile("TASK_DB")` on the operator's terminal instead of the sentence
    // saying which variable is missing and why cleartext is not the answer. The
    // same reason the gateway stringifies `Limits::parse`.
    let db_tls = UpstreamTls::from_env(TASK_DB).map_err(|e| e.to_string())?;

    // STEP 2A OF THE ROTATION-KNOB CUT-OVER (ADR-0569, ADR-0570). The document
    // `yadgarhq/config` renders into the `shared` ConfigMap, mounted at
    // `/etc/yadgar/config/shared/shared.yaml`. There is no compiled-in default
    // behind it any more: an absent, empty, or half-written document refuses the
    // boot and names the file. The chart still sets TLS_ROTATION_POLL_SECS and
    // TLS_ROTATION_SPLAY_MAX_SECS — this binary no longer reads either, but they
    // stay so a rollout that lands this chart before this binary's digest still
    // resolves a schedule on the old one. The runbook is `yadgarhq/deploy`'s
    // MIGRATION_NOTES.md, steps 2a and 2b — NOT this repository's, which has no
    // such section.
    let config = rotate::Configuration::mounted();

    // THE WATCH SET, ASSEMBLED FROM THE RESOLVED CONFIGURATION AND BEFORE THE
    // DIAL (ADR-0523). The baseline is the bytes each file held when this
    // process read them, and every entry is hashed as `watch_set` folds it —
    // deferring the first reading to the watcher's first poll would put the rest
    // of boot inside a window where a kubelet swap quietly becomes the baseline,
    // and the real rotation would never be noticed.
    //
    // THE MOUNTED DOCUMENT JOINS THE SAME SET, as a third `Material` — an
    // operator editing `shared.yaml` now restarts this pod exactly as editing a
    // certificate would.
    //
    // ONE CALL, AND THE SAME ONE A TEST MAKES. This used to be two builder calls
    // forty lines apart in this function, where nothing could reach them: no
    // test spawns this binary, so deleting either compiled and passed
    // everything. The list lives in `rotate::watch_set` now and
    // `tests/assembly.rs` calls it.
    let watch_inputs = rotate::watch_set(tls.as_ref(), db_tls.as_ref(), &config);

    // READ FROM THE SAME DOCUMENT THE WATCH SET JUST JOINED, whether or not any
    // TLS is configured. A value the document names and this binary cannot use
    // is a mistake to refuse, not one to paper over with a default nobody
    // chose — and refusing it here means it is refused on a cleartext
    // deployment too, which is where it would otherwise sit unnoticed until the
    // cut-over.
    let schedule = config.schedule().map_err(|e| e.to_string())?;
    let channel = upstream::connect(&db_host, db_port, db_tls.as_ref())
        .await
        // `refusal` rather than `to_string()` (ledger 733, ledger 740): see its
        // own doc comment for why this is the one site in this file that takes
        // the chain walk. `BalanceError`'s other messages are already complete
        // paragraphs explaining that an empty bundle trusts nobody and that a
        // missing one is not a reason to connect in cleartext — `Tls` is not
        // one of them, and Debug would print the struct and throw all of that
        // away regardless.
        .map_err(|e| refusal(&e))?;
    tracing::info!(
        reresolve_secs = yadgar_dial::reresolve_interval().as_secs(),
        tls = db_tls.is_some(),
        "connected to task-db"
    );

    boot::serve_until_drained(server, tls, channel, watch_inputs, schedule).await
}

#[cfg(test)]
mod tests {
    use super::{env_required, refusal};

    // Each test owns a UNIQUE key. `std::env` is process-global and `cargo test`
    // runs these on threads of one process, so tests sharing a variable name
    // would pass or fail depending on scheduling.

    /// The case a naive test omits, and the only one that proves the value is
    /// USED. A test that merely asserts "boot succeeds" passes just as happily
    /// with a compiled-in default still in place behind the read.
    #[test]
    fn a_set_value_is_returned_verbatim() {
        std::env::set_var("YADGAR_TEST_REQUIRED_PRESENT", "0.0.0.0:8080");
        assert_eq!(
            env_required("YADGAR_TEST_REQUIRED_PRESENT").as_deref(),
            Ok("0.0.0.0:8080")
        );
    }

    #[test]
    fn an_absent_knob_refuses_and_names_itself() {
        std::env::remove_var("YADGAR_TEST_REQUIRED_ABSENT");
        let err = env_required("YADGAR_TEST_REQUIRED_ABSENT").unwrap_err();
        assert!(
            err.contains("YADGAR_TEST_REQUIRED_ABSENT"),
            "the refusal must name the knob, got: {err}"
        );
        assert!(err.contains("NOT SET"), "got: {err}");
    }

    /// **THE CASE THAT DISCRIMINATES.** Helm renders an unset value as `""`, so
    /// a nulled chart value arrives here as set-but-empty rather than as absent.
    /// An implementation that collapses the two into one branch is the defect
    /// this estate found three separate times in one week, so the messages are
    /// asserted to DIFFER rather than merely to exist.
    #[test]
    fn an_empty_knob_refuses_with_its_own_message() {
        std::env::set_var("YADGAR_TEST_REQUIRED_EMPTY", "");
        std::env::remove_var("YADGAR_TEST_REQUIRED_EMPTY_ABSENT");
        let empty = env_required("YADGAR_TEST_REQUIRED_EMPTY").unwrap_err();
        let absent = env_required("YADGAR_TEST_REQUIRED_EMPTY_ABSENT").unwrap_err();
        assert!(empty.contains("set but EMPTY"), "got: {empty}");
        assert!(
            empty.replace("YADGAR_TEST_REQUIRED_EMPTY", "K")
                != absent.replace("YADGAR_TEST_REQUIRED_EMPTY_ABSENT", "K"),
            "empty and absent must not share one message"
        );
    }

    /// THE ONE THING LEDGER 733/740 IS ABOUT, against the REAL error rather
    /// than a fixture that could be shaped to pass.
    ///
    /// `tonic::transport::Error`'s whole `Display` is the two words `transport
    /// error`, and `BalanceError::Tls` interpolates exactly that — so the
    /// sentence `main` used to print for an unusable transport was `TLS could
    /// not be configured: transport error`, which names no file, no key and no
    /// reason. What went wrong sits one layer BELOW tonic's error and is
    /// reachable only by walking `source()`.
    ///
    /// **BOTH RENDERINGS ARE ASSERTED, and the negative one is the point.** A
    /// test that only checked `refusal` contains the reason would pass against
    /// a `to_string()` that happened to carry it; asserting that `to_string()`
    /// does NOT is what shows the layer is genuinely lost, which is the
    /// finding rather than a matched absence.
    ///
    /// MUTATION: replace `refusal`'s body with `error.to_string()` and this
    /// fails.
    ///
    /// The error is produced by `yadgar_task::upstream::connect` — the same
    /// call `main` makes — given a bundle that is a real authority and a
    /// verification domain `rustls::ServerName` refuses. No dial is involved:
    /// the domain is rejected while `yadgar_dial::connect_tls` builds the
    /// tonic endpoint, before anything is resolved.
    #[tokio::test]
    async fn a_refusal_carries_the_layer_below_transport_error() {
        let ca = MintedCa::new();
        let tls = upstream_tls(ca.path(), "not a server name");

        let error = yadgar_task::upstream::connect("task-db", 50051, Some(&tls))
            .await
            .expect_err("a domain rustls cannot parse must refuse before any dial");

        assert!(
            refusal(&error).contains("invalid dns name"),
            "the refusal must carry the layer below tonic's `transport error`; got: {:?}",
            refusal(&error)
        );
        assert!(
            !error.to_string().contains("invalid dns name"),
            "if the head already carried the reason there would be nothing to walk \
             for, and this test would be certifying itself; got: {:?}",
            error.to_string()
        );
    }

    /// `UpstreamTls` assembled the way a DEPLOYMENT assembles it — through
    /// `from_lookup` over the `TASK_DB_TLS_*` names — rather than by hand, so
    /// the test cannot configure a shape `main` could never produce.
    fn upstream_tls(ca_file: &std::path::Path, domain: &str) -> yadgar_task::upstream::UpstreamTls {
        let vars = [
            ("TASK_DB_TLS_ENABLED".to_string(), "1".to_string()),
            (
                "TASK_DB_TLS_CA_FILE".to_string(),
                ca_file.display().to_string(),
            ),
            ("TASK_DB_TLS_DOMAIN".to_string(), domain.to_string()),
        ];
        yadgar_task::upstream::UpstreamTls::from_lookup(yadgar_task::upstream::TASK_DB, |key| {
            vars.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.to_string())
        })
        .expect("a flag, a bundle and a domain are a valid configuration")
        .expect("the flag is set, so TLS is on")
    }

    /// A CA bundle that is a REAL authority, minted per run and deleted after.
    ///
    /// It has to be real: an empty or unparsable bundle is refused by
    /// `TlsOptions::prepare` BEFORE the endpoint is built, so it would produce
    /// `CaEmpty` and never reach the variant under test. Minted rather than
    /// checked in, for the reason every other rig in this repository gives — a
    /// fixture key in the repository is a secret in the repository.
    ///
    /// The name carries a COUNTER as well as the pid: `cargo test` runs these
    /// on threads of one process, and a clock is a timestamp rather than a
    /// nonce (ledger 706, 710, 729).
    struct MintedCa(std::path::PathBuf);

    impl MintedCa {
        fn new() -> Self {
            use rcgen::{
                BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
                KeyUsagePurpose,
            };
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

            let key = KeyPair::generate().expect("a key pair");
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.distinguished_name.push(
                DnType::CommonName,
                "yadgar-task boot-refusal test authority",
            );
            let ca = CertifiedIssuer::self_signed(params, key).expect("a self-signed authority");

            let path = std::env::temp_dir().join(format!(
                "yadgar-task-refusal-{}-{}.pem",
                std::process::id(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::write(&path, ca.pem()).expect("the bundle must be written");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for MintedCa {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
