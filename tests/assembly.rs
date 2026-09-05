//! WHICH FILES THIS DEPLOYMENT WATCHES — the half of the rotation watcher that
//! is this service's own.
//!
//! The watcher's behaviour is `yadgar-lifecycle`'s and is tested there, against
//! the atomic `..data` swap kubelet really performs: that a change ends the
//! watch, that an identical-bytes swap does not, that an unreadable mount is
//! survived, that the leaf rather than the issuer is what the gauge reports.
//! None of that is repeated here. What is here is the claim only this repository
//! can make: **a `task` configured this way reads exactly these files, so
//! exactly these files are watched.**
//!
//! **THE MUTANT THIS FILE EXISTS TO KILL.** The watch set used to be two builder
//! calls in `main.rs`, forty lines apart, and no test in this repository spawns
//! the binary — so deleting either compiled, passed the whole suite, and shipped
//! a process that would never notice that file rotating. The old
//! `tests/tls_rotation.rs` could not catch it: it rebuilt the same assembly by
//! hand, so `main.rs` and the test could disagree while both stayed green. Every
//! case below goes through [`yadgar_task::rotate::watch_set`] — the SAME
//! function `main.rs` calls — so a member deleted from that list turns this red.
//!
//! CERTIFICATES ARE MINTED PER RUN, for the reason `tests/serve_tls.rs` gives: a
//! fixture key in the repository is a secret in the repository, and it expires on
//! a date nobody is watching.

use std::path::{Path, PathBuf};

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

use yadgar_task::rotate::{
    self, Configuration, Presented, CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};
use yadgar_task::serve::{self, ServeTls};
use yadgar_task::upstream::{self, UpstreamTls};

/// The leaf's expiry, and the issuing authority's — DELIBERATELY DIFFERENT and
/// deliberately a decade apart. cert-manager writes the leaf first and the chain
/// after it, so an implementation that parsed the LAST certificate in the file
/// would report an expiry ten years out.
const LEAF_NOT_AFTER: i64 = 1_813_017_600; // 2027-06-15T00:00:00Z

/// The CLIENT leaf's expiry — a year past the serving leaf's, and deliberately
/// so. Both are exported under one metric name, separated only by the `kind`
/// label, so an implementation that gauged the wrong one would land on a
/// plausible number. A distinct date turns that into a failing equality.
const CLIENT_NOT_AFTER: i64 = 1_844_640_000; // 2028-06-15T00:00:00Z

/// One generation of the mount: the file names the chart writes, and their
/// contents.
type Generation = Vec<(String, String)>;

/// A serving certificate and its key, the CA bundle `task-db` is verified
/// against, and the client identity this service presents on that hop — a whole
/// mount's worth of files.
///
/// `tls.pem` holds the leaf FOLLOWED BY the authority that issued it, which is
/// the shape cert-manager writes.
fn generation(san: &str) -> Generation {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_after = date_time_ymd(2037, 6, 15);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-task assembly test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_after = date_time_ymd(2027, 6, 15);
    params.distinguished_name.push(DnType::CommonName, san);
    let leaf = params.signed_by(&key, &ca).unwrap();

    // THE CLIENT LEAF, and it is a DIFFERENT certificate issued for a DIFFERENT
    // purpose (ADR-0516). `ClientAuth` rather than `ServerAuth`, because a peer
    // verifying a client chain refuses a leaf naming the wrong one even though
    // it trusts the issuer perfectly well.
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec![format!("{san}-caller")]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_after = date_time_ymd(2028, 6, 15);
    client_params
        .distinguished_name
        .push(DnType::CommonName, format!("{san}-caller"));
    let client_leaf = client_params.signed_by(&client_key, &ca).unwrap();

    vec![
        ("tls.pem".to_string(), format!("{}{}", leaf.pem(), ca.pem())),
        ("tls-key.pem".to_string(), key.serialize_pem()),
        ("ca.pem".to_string(), ca.pem()),
        (
            "client.pem".to_string(),
            format!("{}{}", client_leaf.pem(), ca.pem()),
        ),
        ("client-key.pem".to_string(), client_key.serialize_pem()),
    ]
}

/// A directory shaped the way kubelet shapes a mounted Secret.
///
/// ```text
///   <root>/..1234-5678/tls.pem
///   <root>/..data      -> ..1234-5678
///   <root>/tls.pem     -> ..data/tls.pem
/// ```
///
/// The service is handed `<root>/tls.pem` and never learns any of the rest,
/// which is exactly what the chart does: a DIRECTORY mount, never `subPath`,
/// because a `subPath` mount is a one-time copy kubelet never refreshes. The
/// shape is kept here even though nothing below rotates the mount, so that what
/// the configuration names is a symlink through `..data` — the path shape the
/// deployed process actually holds.
struct Mount {
    root: PathBuf,
}

impl Mount {
    fn new(files: &Generation) -> Self {
        let root = std::env::temp_dir().join(format!("yadgar-task-assembly-{}", unique()));
        std::fs::create_dir(&root).unwrap();
        let generation = root.join(format!("..{}", unique()));
        std::fs::create_dir(&generation).unwrap();
        for (name, contents) in files {
            std::fs::write(generation.join(name), contents).unwrap();
        }
        std::os::unix::fs::symlink(generation.file_name().unwrap(), root.join("..data")).unwrap();
        for (name, _) in files {
            std::os::unix::fs::symlink(Path::new("..data").join(name), root.join(name)).unwrap();
        }
        Self { root }
    }

    /// The path the SERVICE is given — a symlink through `..data`.
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A name no other case in this run can collide with.
fn unique() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// The mounted document `yadgarhq/config` renders into the `shared` ConfigMap
/// (step 2a) — under its OWN root, never [`Mount`]'s, because the two
/// ConfigMaps land in separate directories in the real deployment and nothing
/// here should suggest otherwise.
fn configuration(body: &str) -> Configuration {
    let root = std::env::temp_dir().join(format!("yadgar-task-assembly-config-{}", unique()));
    std::fs::create_dir_all(root.join("shared")).unwrap();
    std::fs::write(root.join("shared").join("shared.yaml"), body).unwrap();
    Configuration::under(root)
}

/// The listener's transport as a DEPLOYMENT states it — through the same three
/// variables the chart renders.
///
/// **Built from the configuration rather than from paths spelled out here.** A
/// helper naming five paths would prove only that the watcher watches what it is
/// handed; going through `from_lookup` proves that a deployment's CONFIGURATION
/// puts them there, which is the half that can silently be wrong.
fn listener_tls(mount: &Mount) -> ServeTls {
    let vars = [
        ("LISTEN_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "LISTEN_TLS_CERT_FILE".to_string(),
            mount.path("tls.pem").display().to_string(),
        ),
        (
            "LISTEN_TLS_KEY_FILE".to_string(),
            mount.path("tls-key.pem").display().to_string(),
        ),
    ];
    ServeTls::from_lookup(serve::LISTEN, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set")
}

/// How `task-db` is verified, and who this service says it is on that hop.
fn upstream_tls(mount: &Mount) -> UpstreamTls {
    let vars = [
        ("TASK_DB_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "TASK_DB_TLS_CA_FILE".to_string(),
            mount.path("ca.pem").display().to_string(),
        ),
        (
            "TASK_DB_TLS_CLIENT_CERT_FILE".to_string(),
            mount.path("client.pem").display().to_string(),
        ),
        (
            "TASK_DB_TLS_CLIENT_KEY_FILE".to_string(),
            mount.path("client-key.pem").display().to_string(),
        ),
    ];
    UpstreamTls::from_lookup(upstream::TASK_DB, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set")
}

/// EVERY FILE THE CONFIGURATION NAMED IS IN THE WATCH SET, IN ORDER, AND NOTHING
/// ELSE.
///
/// This is the assertion the whole lift was for. Delete `&listener`, `&upstream`
/// or `config` from the list in `rotate::watch_set` and this case goes red;
/// before the lift the equivalent edit in `main.rs` was a mutant nothing killed.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS LAST**, which is what `watch_set`'s
/// fold produces now that step 2a joins it to the set unconditionally.
#[test]
fn the_watch_set_holds_every_file_this_deployment_configured() {
    let mount = Mount::new(&generation("task"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");

    assert_eq!(
        rotate::watch_set(
            Some(&listener_tls(&mount)),
            Some(&upstream_tls(&mount)),
            &config
        )
        .watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
            config.path(),
        ],
        "a fully configured `task` reads six files at boot: the listener's leaf and its \
         key, the bundle `task-db` is verified against, the client identity presented on \
         that hop (ADR-0516), and the mounted configuration document every service now \
         watches (step 2a)"
    );
}

/// THE CERTIFICATE IS FIRST, because it is the one the gauge and the
/// fingerprints speak for — and the CLIENT leaf is a different one.
///
/// Two distinct expiry dates rather than one: an implementation that reported
/// the serving leaf under both `kind` labels would land on a plausible number
/// and pass an assertion that only checked one.
#[test]
fn each_certificate_is_reported_as_the_one_it_is() {
    let mount = Mount::new(&generation("task"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
    let inputs = rotate::watch_set(
        Some(&listener_tls(&mount)),
        Some(&upstream_tls(&mount)),
        &config,
    );

    assert_eq!(
        inputs.watched().first(),
        Some(&mount.path("tls.pem").as_path())
    );
    assert_eq!(inputs.not_after(Presented::Serving), Some(LEAF_NOT_AFTER));
    assert_eq!(inputs.not_after(Presented::Client), Some(CLIENT_NOT_AFTER));
}

/// EACH HALF CONTRIBUTES ON ITS OWN, AND THE MOUNTED DOCUMENT IS THE ONE MEMBER
/// NEITHER HALF CAN DROP.
///
/// It also pins the cleartext default: with neither TLS setting configured this
/// process watches only the mounted configuration document (step 2a) — never
/// nothing, now that every service mounts `shared.yaml` unconditionally — and
/// `rotate::watch` idles until an operator edits that file. `iam` differs too —
/// its enrolment CA (D73) is watched even on a cleartext install, and its chart
/// ships a default for it.
#[test]
fn each_configured_half_contributes_on_its_own() {
    let mount = Mount::new(&generation("task"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");

    assert_eq!(
        rotate::watch_set(None, None, &config).watched(),
        vec![config.path()],
        "with neither TLS setting configured, the mounted configuration document is the \
         only thing watched — it is unconditional, unlike the TLS material either side of it"
    );

    assert_eq!(
        rotate::watch_set(Some(&listener_tls(&mount)), None, &config).watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
            config.path(),
        ],
        "a listener reads its certificate and the key belonging to it, plus the mounted \
         document"
    );

    // TLS ON, NO CLIENT IDENTITY — the state a cut-over passes through, and the
    // one shipped as the default. The CA bundle is watched; nothing else is.
    let vars = [
        ("TASK_DB_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "TASK_DB_TLS_CA_FILE".to_string(),
            mount.path("ca.pem").display().to_string(),
        ),
    ];
    let server_only = UpstreamTls::from_lookup(upstream::TASK_DB, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set");
    assert_eq!(
        rotate::watch_set(None, Some(&server_only), &config).watched(),
        vec![mount.path("ca.pem").as_path(), config.path()],
        "an encrypted hop with no identity watches the bundle, the mounted document, and \
         nothing else"
    );

    assert_eq!(
        rotate::watch_set(None, Some(&upstream_tls(&mount)), &config).watched(),
        vec![
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
            config.path(),
        ],
        "the client certificate and its key both join the set, and the mounted document \
         after them"
    );
}

/// THE GAUGE THIS PROCESS PUBLISHES SAYS `service = "task"`.
///
/// The metric NAME belongs to the crate and is asserted there. What belongs here
/// is the label a dashboard selects this service on: `SERVICE` is a constant in
/// `rotate`, and a value that drifted would blank a panel with nothing failing.
///
/// A plain `#[test]`: `with_local_recorder` is thread-local and
/// `export_not_after` is synchronous, so there is no runtime to involve.
#[test]
fn the_gauge_names_this_service_and_each_certificate_it_holds() {
    let mount = Mount::new(&generation("task"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        rotate::watch_set(
            Some(&listener_tls(&mount)),
            Some(&upstream_tls(&mount)),
            &config,
        )
        .export_not_after()
    });

    let emitted = snapshotter.snapshot().into_vec();
    // A metrics-util built against another `metrics` major links a SECOND
    // facade: everything compiles, nothing is captured, and the assertions below
    // would pass vacuously against an empty snapshot.
    assert_eq!(
        emitted.len(),
        2,
        "one gauge per certificate this process loaded, and nothing else — check \
         for a duplicate `metrics` crate"
    );

    let mut seen: Vec<(Vec<(String, String)>, f64)> = emitted
        .iter()
        .map(|(composite, _unit, _description, value)| {
            let key = composite.key();
            assert_eq!(key.name(), CERTIFICATE_NOT_AFTER);
            let labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            let seconds = match value {
                DebugValue::Gauge(seconds) => seconds.into_inner(),
                other => panic!("expected a gauge, got {other:?}"),
            };
            (labels, seconds)
        })
        .collect();
    seen.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        seen,
        vec![
            (
                vec![
                    ("service".to_string(), "task".to_string()),
                    ("kind".to_string(), "client".to_string()),
                ],
                CLIENT_NOT_AFTER as f64
            ),
            (
                vec![
                    ("service".to_string(), "task".to_string()),
                    ("kind".to_string(), "serving".to_string()),
                ],
                LEAF_NOT_AFTER as f64
            ),
        ],
        "each gauge carries the expiry of the leaf it names, and the two are not \
         interchangeable: an expired CLIENT leaf STOPS this hop (ADR-0516)"
    );
}

/// THE UNREADABLE-FILES GAUGE REACHES THE FACADE THIS BINARY EXPORTS FROM, AND
/// A ZERO IS ONE OF ITS VALUES.
///
/// `yadgar-lifecycle` v0.1.2 added `yadgar_rotation_watched_files_unreadable`
/// and the crate tests what it counts. What only this repository can say is that
/// the series a dashboard would select — this service's name, on this service's
/// own watch set — is the one that arrives, and that it arrives when NOTHING is
/// wrong. A gauge appearing only on the bad day cannot be told apart from an
/// exporter that is not running.
///
/// **THE FILE REMOVED HERE IS THE CLIENT KEY.** It carries no expiry of its
/// own, so the case above cannot speak for it at all — and it is half of the
/// identity whose loss stops this service reaching `task-db` (ADR-0516).
///
/// **NOTHING IS REGISTERED FOR IT AT THE SERVICE END, and this is the check that
/// says so rather than an assumption.** `yadgar_telemetry::metrics::install_prometheus`
/// installs `PrometheusBuilder::new()` with no allow-list and no idle timeout,
/// and `metrics-exporter-prometheus`'s `render` walks the gauge snapshot and
/// consults `descriptions` only for the `# HELP` line — so an undescribed gauge
/// renders, and no `describe_gauge!` call is needed here.
///
/// A plain `#[test]`, for the reason the case above gives.
#[test]
fn the_unreadable_gauge_carries_this_service_and_is_published_at_zero_too() {
    let mount = Mount::new(&generation("task"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
    let inputs = rotate::watch_set(
        Some(&listener_tls(&mount)),
        Some(&upstream_tls(&mount)),
        &config,
    );

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let gone = mount.path("client-key.pem");

    let (nothing_wrong, at_zero, one_gone, at_one) =
        metrics::with_local_recorder(&recorder, || {
            let nothing_wrong = inputs.export_unreadable();
            let at_zero = snapshotter.snapshot().into_vec();
            std::fs::remove_file(&gone).expect("the mount is this test's own");
            let one_gone = inputs.export_unreadable();
            let at_one = snapshotter.snapshot().into_vec();
            (nothing_wrong, at_zero, one_gone, at_one)
        });

    assert!(
        nothing_wrong.is_empty(),
        "every one of the five files this mount names is readable: {nothing_wrong:?}"
    );
    assert_eq!(
        one_gone,
        vec![gone.display().to_string()],
        "the client key was removed, so it is the one unreadable file and the four \
         beside it are not"
    );

    for (emitted, expected) in [(at_zero, 0.0_f64), (at_one, 1.0_f64)] {
        // A metrics-util built against another `metrics` major links a SECOND
        // facade: everything compiles, nothing is captured, and the assertions
        // below would pass vacuously against an empty snapshot.
        assert_eq!(
            emitted.len(),
            1,
            "one series for the whole watch set, labelled by service and by nothing \
             per-path — check for a duplicate `metrics` crate"
        );
        let (composite, _unit, _description, value) = &emitted[0];
        let key = composite.key();
        assert_eq!(key.name(), WATCHED_FILES_UNREADABLE);
        let labels: Vec<(String, String)> = key
            .labels()
            .map(|l| (l.key().to_string(), l.value().to_string()))
            .collect();
        assert_eq!(
            labels,
            vec![("service".to_string(), "task".to_string())],
            "a path label would make this metric's cardinality a property of a \
             deployment's configuration"
        );
        match value {
            DebugValue::Gauge(count) => assert_eq!(count.into_inner(), expected),
            other => panic!("expected a gauge, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// THE CHART STILL SPEAKS TWO LANGUAGES TO THE ROTATION WATCHER (STEP 2A).
//
// Before v0.2.0, `Schedule::from_lookup` answered an unmatched key with a
// DEFAULT rather than an error, so a variable nobody read was silent in both
// directions — and this file used to derive the chart's env-var spelling from
// the TEMPLATE and feed it straight to that reader, a real coupling test. Both
// `from_lookup` and `from_env` are deleted from `yadgar-lifecycle` now, and
// this binary reads `rotate::Configuration::mounted()` instead (`main.rs`), so
// that particular coupling has nothing left to assert.
//
// TWO THINGS STILL HAVE TO HOLD, ONE PER SOURCE. The chart must keep rendering
// the two environment variables the OLD binary reads — asserted below as
// literal strings, which is the honest form now that no reader in THIS binary
// exists to derive them from. And the chart's `mountPath` must keep agreeing
// with the path the NEW binary reads, which `yadgarhq/config`'s README calls
// out by name ("The mount path and that constant must agree. They disagree
// LOUDLY") — asserted below by deriving the expected path from
// `Configuration::mounted()` itself, so a rename in `yadgar-lifecycle` turns
// this red rather than agreeing with a copy of itself.
//
// WHAT NEITHER COVERS, stated rather than implied: the anchor for the first is
// the `.Values` key as the TEMPLATE spells it, and a `values.yaml` renamed out
// from under an unchanged template is a different defect that `helm` itself
// catches — `required` fails the render.
// ---------------------------------------------------------------------------

/// The template this service is deployed from, read at COMPILE TIME so this can
/// never pass against a chart that is not in the tree.
const DEPLOYMENT: &str = include_str!("../chart/templates/deployment.yaml");

/// The environment variable name the chart renders for one `values.yaml` key.
///
/// EXACTLY ONE reference is required rather than assumed. "The nearest preceding
/// `- name:`" silently picks the wrong entry if a second reference to the same
/// key is ever added, and a rig that picks the wrong entry reports on a variable
/// nobody asked about.
fn rendered_env_name(values_key: &str) -> String {
    let lines: Vec<&str> = DEPLOYMENT.lines().collect();
    let referencing: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(values_key))
        .map(|(at, _)| at)
        .collect();
    assert_eq!(
        referencing.len(),
        1,
        "the rig expects exactly one reference to {values_key} in the deployment template and \
         found {}; it cannot say which environment variable that key names",
        referencing.len()
    );

    lines[..=referencing[0]]
        .iter()
        .rev()
        .find_map(|line| line.trim().strip_prefix("- name: "))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            panic!("no `- name:` line precedes the reference to {values_key} in the template")
        })
}

/// STEP 2A KEEPS BOTH SOURCES LIVE (MIGRATION_NOTES.md, ADR-0569/ADR-0570).
///
/// `rotate::Schedule::from_env` and `from_lookup` are gone from
/// `yadgar-lifecycle` v0.2.0, and this binary now reads its schedule from
/// `rotate::Configuration::mounted()` instead — so the coupling this test used
/// to assert (the chart's rendered variable feeds `Schedule::from_lookup`) no
/// longer exists to test. What still has to hold, and what this asserts
/// instead, is that the chart goes on rendering BOTH variables under their
/// established names: Argo takes this chart from HEAD the moment this pull
/// request merges, while the image is pinned by digest minutes later from a
/// separate pipeline, so a pod can roll onto the OLD binary — which still
/// reads these two variables and has no other source. Deleting either is step
/// 2b, and only after that digest has landed in `yadgarhq/argocd`.
#[test]
fn the_chart_still_renders_the_tls_rotation_variables_for_the_old_binary() {
    assert_eq!(
        rendered_env_name(".Values.tlsRotation.pollSeconds"),
        "TLS_ROTATION_POLL_SECS",
        "a pod that rolls onto the old binary before this release's digest reaches \
         yadgarhq/argocd reads its poll interval from this variable and no other source"
    );
    assert_eq!(
        rendered_env_name(".Values.tlsRotation.splayMaxSeconds"),
        "TLS_ROTATION_SPLAY_MAX_SECS",
        "a pod that rolls onto the old binary before this release's digest reaches \
         yadgarhq/argocd reads its splay ceiling from this variable and no other source"
    );
}

/// THE CHART'S `mountPath` AND THE PATH THIS BINARY ACTUALLY READS MUST AGREE.
///
/// `yadgarhq/config`'s README states the safety property by name: "The mount
/// path and that constant must agree. They disagree LOUDLY — a mismatch
/// produces a refusal naming the path this process looked in." Naming the
/// expected path a second time here would agree with itself for ever, so it is
/// derived from `Configuration::mounted()` — the exact call `main.rs` makes —
/// and a rename inside `yadgar-lifecycle` turns this red instead.
#[test]
fn the_chart_mounts_the_shared_configmap_where_this_binary_looks_for_it() {
    let mounted = Configuration::mounted();
    let shared_dir = mounted
        .path()
        .parent()
        .expect("the mounted document has a parent directory")
        .display()
        .to_string();

    assert!(
        DEPLOYMENT
            .lines()
            .any(|line| line.trim() == format!("mountPath: {shared_dir}")),
        "yadgar_lifecycle::rotate::Configuration::mounted() reads {}, but no volumeMount in \
         this chart's deployment.yaml names {shared_dir} as its mountPath — a pod would exit \
         at boot naming a path this chart never mounts",
        mounted.path().display()
    );
}
