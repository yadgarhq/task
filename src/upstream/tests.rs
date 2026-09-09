//! `upstream`'s unit tests, in the submodule file Rust's own convention gives
//! them (`#[cfg(test)] mod tests;`) rather than inline in `upstream.rs`.
//!
//! THE PARENT WAS OVER THE FILE CEILING AND ITS PRODUCTION CODE WAS NOT. 705
//! lines measured, of which 277 were production and 428 were this module. There
//! is no seam inside those 277 lines, so cutting them in two would have been a
//! split made to satisfy a number. Moving the tests to the file their convention
//! names is the honest answer, and the ceiling's own exemption is written for
//! exactly this layout (ADR-0636).
//!
//! Nothing here changed on the way over except the indentation: `use super::*;`
//! reaches the same items from a child module that it reached from an inline
//! one.

use super::*;

/// The values below are SENTINELS: nothing in `upstream.rs` could produce
/// either of them, so a test that sees one saw it travel from the lookup.
const SENTINEL_CA: &str = "/etc/yadgar/aardvark-9f3c/bundle.pem";
const SENTINEL_CLIENT_CERT: &str = "/etc/yadgar/aardvark-9f3c/task-caller.pem";
const SENTINEL_CLIENT_KEY: &str = "/etc/yadgar/aardvark-9f3c/task-caller-key.pem";
const SENTINEL_DOMAIN: &str = "task-db.verified-as-this.invalid";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
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
