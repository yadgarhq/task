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
use std::time::Duration;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

use yadgar_task::rotate::{self, Presented, CERTIFICATE_NOT_AFTER};
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
/// This is the assertion the whole lift was for. Delete `&listener` or
/// `&upstream` from the list in `rotate::watch_set` and this case goes red;
/// before the lift the equivalent edit in `main.rs` was a mutant nothing killed.
#[test]
fn the_watch_set_holds_every_file_this_deployment_configured() {
    let mount = Mount::new(&generation("task"));

    assert_eq!(
        rotate::watch_set(Some(&listener_tls(&mount)), Some(&upstream_tls(&mount))).watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
        ],
        "a fully configured `task` reads five files at boot: the listener's leaf and its \
         key, the bundle `task-db` is verified against, and the client identity presented \
         on that hop (ADR-0516)"
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
    let inputs = rotate::watch_set(Some(&listener_tls(&mount)), Some(&upstream_tls(&mount)));

    assert_eq!(
        inputs.watched().first(),
        Some(&mount.path("tls.pem").as_path())
    );
    assert_eq!(inputs.not_after(Presented::Serving), Some(LEAF_NOT_AFTER));
    assert_eq!(inputs.not_after(Presented::Client), Some(CLIENT_NOT_AFTER));
}

/// EACH HALF CONTRIBUTES ON ITS OWN, and in THIS service nothing configured is
/// genuinely nothing to watch.
///
/// `iam` differs — its enrolment CA (D73) is watched too, and its chart ships a
/// default for it, so a cleartext `iam` still has a non-empty set. Here the
/// transport is the only security material read, so a cleartext deployment
/// watches nothing and `rotate::watch` idles for the life of the pod.
#[test]
fn each_configured_half_contributes_on_its_own() {
    let mount = Mount::new(&generation("task"));

    assert!(
        rotate::watch_set(None, None).is_empty(),
        "nothing configured is nothing to watch"
    );

    assert_eq!(
        rotate::watch_set(Some(&listener_tls(&mount)), None).watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
        ],
        "a listener reads its certificate and the key belonging to it"
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
        rotate::watch_set(None, Some(&server_only)).watched(),
        vec![mount.path("ca.pem").as_path()],
        "an encrypted hop with no identity watches the bundle and nothing else"
    );

    assert_eq!(
        rotate::watch_set(None, Some(&upstream_tls(&mount))).watched(),
        vec![
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
        ],
        "the client certificate and its key both join the set"
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
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        rotate::watch_set(Some(&listener_tls(&mount)), Some(&upstream_tls(&mount)))
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

// ---------------------------------------------------------------------------
// THE TWO NAMES THE CHART RENDERS, AND THE TWO NAMES THIS BINARY READS.
//
// `Schedule::from_lookup` answers an unmatched key with a DEFAULT rather than an
// error, so a variable nobody reads is silent in both directions: the chart goes
// on rendering it and the process goes on polling every 60s. `yadgar-lifecycle`
// pins both spellings in its own unit tests, so a rename inside the crate breaks
// the crate loudly — what is left uncovered is narrower and lives HERE: a
// spelling in THIS chart that no longer matches the one the crate reads.
//
// The names are taken OUT OF THE TEMPLATE rather than written down again,
// anchored on the `values.yaml` key, because the variable's spelling is the
// thing under test and a copy of it here would agree with itself for ever.
//
// WHAT THIS DOES NOT COVER, stated rather than implied: the anchor is the
// `.Values` key as the TEMPLATE spells it. A `values.yaml` renamed out from
// under an unchanged template is a different defect, and `helm` catches that one
// itself — `required` fails the render.
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

/// The schedule an operator sets through this chart is the schedule this process
/// runs on.
#[test]
fn the_chart_renders_the_schedule_variables_this_binary_reads() {
    let poll_key = rendered_env_name(".Values.tlsRotation.pollSeconds");
    let splay_key = rendered_env_name(".Values.tlsRotation.splayMaxSeconds");

    // NEITHER SENTINEL IS A DEFAULT — `from_lookup` falls back to 60s and 300s,
    // so a sentinel equal to either would pass against a name nothing reads.
    let schedule = rotate::Schedule::from_lookup(|key| match key {
        _ if key == poll_key => Some("17".to_owned()),
        _ if key == splay_key => Some("941".to_owned()),
        _ => None,
    })
    .expect("a schedule of two whole numbers of seconds");

    assert_eq!(
        schedule.poll(),
        Duration::from_secs(17),
        "the chart renders {poll_key} and the watcher reads something else, so the poll interval \
         an operator sets through this chart never reaches the process"
    );
    assert_eq!(
        schedule.splay_max(),
        Duration::from_secs(941),
        "the chart renders {splay_key} and the watcher reads something else, so every pod would \
         exit on a rotated certificate inside the default window rather than the one this \
         deployment states"
    );
}
