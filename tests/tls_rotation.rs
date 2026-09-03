//! The rotation watcher, proved against the directory shape kubelet actually
//! writes.
//!
//! **A test that overwrites a file in place passes against a broken
//! implementation**, so nothing here does that. Every case builds the mount the
//! way kubelet builds a mounted Secret — a timestamped data directory, a
//! `..data` symlink pointing at it, and one symlink per key pointing through
//! `..data` — and rotates it by creating a NEW timestamped directory and
//! `rename`ing a replacement `..data` over the old one. That rename is the
//! atomic swap, and it is the only event the watcher ever sees in production.
//!
//! **THE NEGATIVE CASE IS THE LOAD-BEARING ONE.** After the swap every path
//! resolves to a different inode with a fresh modification time, so an
//! mtime-based watcher fires on EVERY swap — including the ones that changed
//! nothing. [`an_atomic_swap_of_identical_bytes_does_not_end_the_watch`] is what
//! separates a content hash from an mtime, and it is the case to mutate when
//! checking that this suite still bites.
//!
//! **The failure mode this must never grow.** If the watcher dies, the process
//! keeps serving the certificate it loaded — today's behaviour, never worse.
//! [`a_mount_that_cannot_be_read_does_not_end_the_watch`] and
//! [`nothing_configured_never_ends_the_watch`] pin that: neither is allowed to
//! end the watch, because ending it exits the process.
//!
//! CERTIFICATES ARE MINTED PER RUN, for the reason `tests/serve_tls.rs` gives:
//! a fixture key in the repository is a secret in the repository, and it expires
//! on a date nobody is watching.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tokio::time::timeout;

use yadgar_task::rotate::{self, Inputs, Presented, Schedule, CERTIFICATE_NOT_AFTER};
use yadgar_task::serve::{self, ServeTls};
use yadgar_task::upstream::{self, UpstreamTls};

/// Short enough that a case finishes quickly, long enough that the watcher
/// really does go round its loop rather than reading everything in one pass.
const POLL: Duration = Duration::from_millis(20);

/// How long a case waits for a watch that SHOULD end. Generous: the assertion
/// is about whether it ends at all, never about how fast.
const GENEROUS: Duration = Duration::from_secs(5);

/// How long a case waits before concluding a watch will NOT end. Many poll
/// intervals, so a watcher that was going to fire has had every chance to.
const PATIENT: Duration = Duration::from_millis(600);

/// The leaf's expiry, and the issuing authority's — DELIBERATELY DIFFERENT and
/// deliberately a decade apart. cert-manager writes the leaf first and the
/// chain after it, so an implementation that parses the LAST certificate in the
/// file reports an expiry ten years out, and the gauge that exists to make a
/// stale leaf loud goes quiet instead.
const LEAF_NOT_AFTER: i64 = 1_813_017_600; // 2027-06-15T00:00:00Z
const CA_NOT_AFTER: i64 = 2_128_636_800; // 2037-06-15T00:00:00Z

/// The CLIENT leaf's expiry — a year past the serving leaf's, and deliberately
/// so. Both are exported under one metric name, separated only by the `kind`
/// label, so an implementation that gauged the wrong one would land on a
/// plausible number. A distinct date turns that into a failing equality.
const CLIENT_NOT_AFTER: i64 = 1_844_640_000; // 2028-06-15T00:00:00Z

/// One generation of the mount: the file names the chart writes, and their
/// contents.
type Generation = Vec<(String, String)>;

/// A serving certificate and its key, as a whole mount's worth of files.
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
        .push(DnType::CommonName, "yadgar-task rotation test authority");
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
    // it trusts the issuer perfectly well — the same authority signs both here,
    // which is what the reference deployment does.
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

/// The same generation with ONE file's contents replaced.
///
/// **Every other byte is identical**, which is what makes a case built on this
/// prove that the named file is watched. A whole-generation swap cannot: it
/// changes everything at once, so an implementation hashing only the first file
/// passes it.
fn with_replaced(base: &Generation, name: &str, contents: &str) -> Generation {
    base.iter()
        .map(|(n, c)| {
            let replaced = if n == name { contents } else { c.as_str() };
            (n.clone(), replaced.to_string())
        })
        .collect()
}

/// The same generation with the contents of two files EXCHANGED.
///
/// Every byte in the mount is still present, and no file is longer or shorter
/// than before — so an implementation that hashed the concatenation without
/// regard to which file each byte came from would see no change at all.
fn with_exchanged(base: &Generation, one: &str, other: &str) -> Generation {
    let get = |name: &str| {
        base.iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.clone())
            .expect("the mount holds that file")
    };
    let (a, b) = (get(one), get(other));
    base.iter()
        .map(|(n, c)| match n.as_str() {
            m if m == one => (n.clone(), b.clone()),
            m if m == other => (n.clone(), a.clone()),
            _ => (n.clone(), c.clone()),
        })
        .collect()
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
/// because a `subPath` mount is a one-time copy kubelet never refreshes.
struct Mount {
    root: PathBuf,
}

impl Mount {
    /// Write the first generation and the symlinks that point at it.
    fn new(files: &Generation) -> Self {
        let root = std::env::temp_dir().join(format!("yadgar-task-rotation-{}", unique()));
        std::fs::create_dir(&root).unwrap();
        let mount = Self { root };
        mount.swap(files);
        for (name, _) in files {
            std::os::unix::fs::symlink(Path::new("..data").join(name), mount.path(name)).unwrap();
        }
        mount
    }

    /// The path the SERVICE is given — a symlink through `..data`.
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// What kubelet does when the Secret changes: write a whole new generation,
    /// then move a replacement `..data` symlink over the old one.
    ///
    /// **The `rename` is the point.** It is atomic, so a reader never sees half
    /// a generation, and it leaves every path the service holds resolving to a
    /// DIFFERENT inode with a fresh modification time — which is why an mtime
    /// check cannot tell a real rotation from a no-op one.
    fn swap(&self, files: &Generation) {
        let generation = self.root.join(format!("..{}", unique()));
        std::fs::create_dir(&generation).unwrap();
        for (name, contents) in files {
            std::fs::write(generation.join(name), contents).unwrap();
        }
        self.point_data_at(generation.file_name().unwrap());
    }

    /// Point `..data` at a generation that does not exist, so every path the
    /// service holds becomes unreadable without any of them being deleted.
    ///
    /// A transient state, and one the watcher must survive rather than act on.
    fn break_it(&self) {
        self.point_data_at("..no-such-generation".as_ref());
    }

    fn point_data_at(&self, generation: &std::ffi::OsStr) {
        let staged = self.root.join("..data_tmp");
        let _ = std::fs::remove_file(&staged);
        std::os::unix::fs::symlink(generation, &staged).unwrap();
        std::fs::rename(&staged, self.root.join("..data")).unwrap();
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

/// The inputs a TLS deployment of this service reads at boot, **assembled from
/// the resolved configuration exactly as `main` assembles them**: the listener's
/// certificate and key, the CA bundle `task-db` is verified against, and the
/// client certificate and key this service presents to `task-db` (ADR-0516).
///
/// **Built through the two config-taking methods rather than by naming five
/// paths.** A helper that spelled the paths out would prove only that `rotate`
/// watches what it is handed — never that a deployment's CONFIGURATION puts them
/// there, which is the half that can silently be wrong. That distinction is not
/// theoretical: in `iam`, where this file began, a builder that quietly added
/// nothing passed every rotation case in it.
fn inputs(mount: &Mount) -> Inputs {
    Inputs::default()
        .listener(Some(&listener_tls(mount)))
        .upstream(Some(&upstream_tls(mount)))
}

/// The listener's transport as a DEPLOYMENT states it — through the same three
/// variables the chart renders.
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

/// Rotate the mount once the watcher has had time to take its boot reading.
///
/// Sequencing rather than a guess: the watcher reads its baseline before its
/// first sleep, so a swap that lands several poll intervals later is
/// unambiguously a CHANGE rather than the state it started from.
fn swap_shortly(mount: &Arc<Mount>, files: Generation) {
    let mount = Arc::clone(mount);
    tokio::spawn(async move {
        tokio::time::sleep(POLL * 4).await;
        mount.swap(&files);
    });
}

/// THE CASE THE CHANGE EXISTS FOR. cert-manager rewrites the Secret, kubelet
/// swaps `..data`, and the process that read the old certificate at boot ends
/// its watch so it can be restarted onto the new one.
#[tokio::test]
async fn an_atomic_swap_of_a_new_certificate_ends_the_watch() {
    let mount = Arc::new(Mount::new(&generation("task")));
    let watched = inputs(&mount);
    swap_shortly(&mount, generation("task"));

    timeout(
        GENEROUS,
        rotate::watch_with_seed(watched, Schedule::new(POLL, Duration::ZERO), 0),
    )
    .await
    .expect("a renewed certificate behind an atomic ..data swap must end the watch");
}

/// THE CASE THAT SEPARATES A HASH FROM AN mtime, and the one to mutate when
/// checking this suite still bites.
///
/// Every path resolves to a new inode with a new modification time, and not one
/// byte the process read has changed. Ending the watch here would restart both
/// replicas for nothing, on every kubelet resync, forever.
#[tokio::test]
async fn an_atomic_swap_of_identical_bytes_does_not_end_the_watch() {
    let files = generation("task");
    let mount = Arc::new(Mount::new(&files));
    let watched = inputs(&mount);
    swap_shortly(&mount, files);

    assert!(
        timeout(
            PATIENT,
            rotate::watch_with_seed(watched, Schedule::new(POLL, Duration::ZERO), 0)
        )
        .await
        .is_err(),
        "the bytes are identical, so nothing rotated; only an mtime check fires here"
    );
}

/// A mount that cannot be read is a TRANSIENT state, not a rotation. Acting on
/// it would exit the process over a directory kubelet is halfway through
/// rewriting — a watcher whose failure is WORSE than not having one.
#[tokio::test]
async fn a_mount_that_cannot_be_read_does_not_end_the_watch() {
    let mount = Arc::new(Mount::new(&generation("task")));
    let watched = inputs(&mount);

    let breaker = Arc::clone(&mount);
    tokio::spawn(async move {
        tokio::time::sleep(POLL * 4).await;
        breaker.break_it();
    });

    assert!(
        timeout(
            PATIENT,
            rotate::watch_with_seed(watched, Schedule::new(POLL, Duration::ZERO), 0)
        )
        .await
        .is_err(),
        "an unreadable file is not a changed one; the process must keep serving what it loaded"
    );
}

/// THE DEFAULT. TLS is off, so nothing was read and there is nothing to watch —
/// and a watch that ended here would exit a process that has no certificate at
/// all.
#[tokio::test]
async fn nothing_configured_never_ends_the_watch() {
    assert!(
        timeout(
            PATIENT,
            rotate::watch_with_seed(Inputs::default(), Schedule::new(POLL, Duration::ZERO), 0)
        )
        .await
        .is_err(),
        "an unconfigured deployment has no TLS inputs and must never exit on their account"
    );
}

/// THE SPLAY IS WAITED OUT BEFORE THE WATCH ENDS.
///
/// Both replicas see the refreshed file inside the same kubelet sync window, so
/// an unsplayed exit drops both at once. A PDB does not govern a self-exit —
/// this wait is the only thing that does.
///
/// `u64::MAX` is the top of the seed range, so the splay is the whole configured
/// maximum and the assertion is an equality rather than a coin toss.
#[tokio::test]
async fn the_watch_ends_only_after_the_splay() {
    let mount = Arc::new(Mount::new(&generation("task")));
    let watched = inputs(&mount);
    swap_shortly(&mount, generation("task"));

    let splay = Duration::from_millis(700);
    let started = Instant::now();
    timeout(
        GENEROUS,
        rotate::watch_with_seed(watched, Schedule::new(POLL, splay), u64::MAX),
    )
    .await
    .expect("the watch must still end");
    assert!(
        started.elapsed() >= splay,
        "the watch ended after {:?}, which is inside the {splay:?} splay",
        started.elapsed()
    );
}

/// THE EXPIRY IS THE LEAF'S, NEVER THE CHAIN'S.
///
/// `tls.pem` holds the leaf followed by the authority that issued it, and the
/// authority outlives it by a decade. A gauge reporting the CA's expiry is
/// worse than no gauge: it reads healthy for ten years while the certificate
/// the listener is actually serving ages out.
#[tokio::test]
async fn the_expiry_reported_is_the_leaf_certificate_not_the_chain() {
    let mount = Mount::new(&generation("task"));

    assert_eq!(
        inputs(&mount).not_after(Presented::Serving),
        Some(LEAF_NOT_AFTER),
        "the first certificate in the file is the one being served"
    );
    assert_ne!(
        inputs(&mount).not_after(Presented::Serving),
        Some(CA_NOT_AFTER),
        "reporting the issuer's expiry would keep the gauge green for a decade"
    );
    // The CLIENT leaf is written the same way — leaf, then the authority that
    // signed it — so the same mistake is available on the same file and would
    // report a CA expiry a decade out for the material ADR-0516 makes
    // load-bearing for availability.
    assert_eq!(
        inputs(&mount).not_after(Presented::Client),
        Some(CLIENT_NOT_AFTER),
        "the first certificate in the client file is the one being presented"
    );
}

/// The fingerprint NAMES the certificate, so two different certificates cannot
/// share one — that is the whole of what a log line saying "which certificate am
/// I on" is worth.
#[tokio::test]
async fn the_fingerprint_distinguishes_two_certificates() {
    let one = Mount::new(&generation("task"));
    let other = Mount::new(&generation("task"));

    let a = inputs(&one)
        .fingerprint(Presented::Serving)
        .expect("a certificate was read");
    let b = inputs(&other)
        .fingerprint(Presented::Serving)
        .expect("a certificate was read");
    assert_eq!(a.len(), 64, "SHA-256 over the leaf's DER, hex");
    assert_ne!(a, b, "two certificates must not share a fingerprint");

    // AND THE TWO KINDS ARE NOT EACH OTHER. One process holds both, so a
    // fingerprint that answered "which certificate am I on" with the wrong one
    // would read as a plausible answer.
    let client = inputs(&one)
        .fingerprint(Presented::Client)
        .expect("a client certificate was read");
    assert_ne!(
        a, client,
        "the serving and client leaves are different files"
    );
}

/// THE GAUGE LANDS UNDER THE NAME AND THE LABEL A DASHBOARD QUERIES.
///
/// A typo in either string compiles, passes clippy, and passes every other case
/// in this file — and produces a series nothing asks for. That is
/// indistinguishable from a certificate that never expires. `not_after` being
/// right is not the same claim as it being EXPORTED right.
///
/// A plain `#[test]`: `with_local_recorder` is thread-local and
/// `export_not_after` is synchronous, so there is no runtime to involve.
#[test]
fn the_expiry_is_exported_under_the_name_a_dashboard_queries() {
    assert_eq!(
        CERTIFICATE_NOT_AFTER, "yadgar_tls_certificate_not_after_seconds",
        "the name is an interface to Grafana; renaming it blanks the panel"
    );

    let mount = Mount::new(&generation("task"));
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || inputs(&mount).export_not_after());

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

    // BOTH LABELS ARE BOUNDED. `kind` has exactly two values and always will, so
    // it costs two series rather than one per rotation — which is what D67's
    // rule is actually about. A fingerprint or a path here would not be.
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

/// NOTHING IS PUBLISHED WHEN THERE IS NOTHING TO PUBLISH. An invented number is
/// worse than a missing series: a dashboard cannot tell it apart from a real
/// one.
#[test]
fn no_certificate_exports_no_gauge() {
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || Inputs::default().export_not_after());
    assert!(snapshotter.snapshot().into_vec().is_empty());
}

/// EVERY WATCHED FILE IS WATCHED, one at a time.
///
/// **This is the case a whole-generation swap cannot make.** `swap_shortly`
/// rewrites all four files, so an implementation that hashed only the first
/// would pass every other case in this file — measured, and it did. Here each
/// file is rotated with the other three left byte-identical, so a file missing
/// from the watch set is a case that hangs.
#[tokio::test]
async fn each_watched_file_ends_the_watch_on_its_own() {
    for name in [
        "tls.pem",
        "tls-key.pem",
        "ca.pem",
        "client.pem",
        "client-key.pem",
    ] {
        let base = generation("task");
        let mount = Arc::new(Mount::new(&base));
        let watched = inputs(&mount);

        // A replacement minted independently, so the new contents cannot
        // coincide with the old by construction.
        let fresh = generation("task");
        let replacement = fresh
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.clone())
            .expect("the fresh generation holds that file");
        swap_shortly(&mount, with_replaced(&base, name, &replacement));

        timeout(
            GENEROUS,
            rotate::watch_with_seed(watched, Schedule::new(POLL, Duration::ZERO), 0),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("rotating {name} alone did not end the watch, so it is not being watched")
        });
    }
}

/// TWO FILES EXCHANGING CONTENTS IS A ROTATION, not a wash.
///
/// The mount holds exactly the same bytes afterwards, and every file is the
/// same length as before. Only a digest that is per-file and POSITIONAL sees it.
#[tokio::test]
async fn exchanging_the_contents_of_two_watched_files_ends_the_watch() {
    let base = generation("task");
    let mount = Arc::new(Mount::new(&base));
    let watched = inputs(&mount);
    swap_shortly(&mount, with_exchanged(&base, "tls-key.pem", "ca.pem"));

    timeout(
        GENEROUS,
        rotate::watch_with_seed(watched, Schedule::new(POLL, Duration::ZERO), 0),
    )
    .await
    .expect("the same bytes in different files are different inputs");
}

/// THE BASELINE IS THE BYTES THE PROCESS READ, NOT A LATER READING.
///
/// `Inputs` is built beside the code that loads each file. If it merely
/// remembered paths and read them when the watcher first polled, everything
/// between — the `task-db` dial, the broker connect — would be a window in which
/// a kubelet swap silently became the baseline: the rotation would never be
/// noticed, and the gauge would describe a certificate the listener is not
/// serving. Here the swap lands BEFORE the watch begins, and both must still
/// speak for the original.
#[tokio::test]
async fn the_baseline_is_what_was_loaded_not_what_is_on_disk_later() {
    let mount = Arc::new(Mount::new(&generation("task")));
    let watched = inputs(&mount);
    let loaded = watched
        .fingerprint(Presented::Serving)
        .expect("a certificate was read");
    let loaded_client = watched
        .fingerprint(Presented::Client)
        .expect("a client certificate was read");

    // The whole mount is replaced before the watcher has polled once.
    mount.swap(&generation("task"));

    assert_eq!(
        watched.fingerprint(Presented::Serving),
        Some(loaded),
        "the fingerprint must name the loaded certificate, not the one now on disk"
    );
    assert_eq!(
        watched.fingerprint(Presented::Client),
        Some(loaded_client),
        "and the same for the client leaf, which fails harder when it is stale"
    );
    assert_eq!(
        watched.not_after(Presented::Serving),
        Some(LEAF_NOT_AFTER),
        "and so must the expiry the gauge carries"
    );
    timeout(
        GENEROUS,
        rotate::watch_with_seed(watched, Schedule::new(POLL, Duration::ZERO), 0),
    )
    .await
    .expect("a swap that landed before the first poll is still a rotation");
}

/// THE CLIENT CERTIFICATE AND ITS KEY ARE IN THE WATCH SET, and MEMBERSHIP is
/// the only shape that proves it.
///
/// Every rotation case builds its inputs through the same two methods, so a
/// `rotate::Inputs::upstream` that quietly added nothing for the identity would
/// leave a suite built on whole-mount swaps green. This one and
/// `each_watched_file_ends_the_watch_on_its_own` are what go red for it.
#[tokio::test]
async fn the_watch_set_holds_every_file_the_configuration_named() {
    let mount = Mount::new(&generation("task"));
    let watched: Vec<String> = inputs(&mount)
        .watched()
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    for name in [
        "tls.pem",
        "tls-key.pem",
        "ca.pem",
        "client.pem",
        "client-key.pem",
    ] {
        let expected = mount.path(name).display().to_string();
        assert!(
            watched.contains(&expected),
            "{name} is not in the watch set, so a rotation of it would never be noticed. \
             Watching: {watched:?}"
        );
    }
    assert_eq!(watched.len(), 5, "and nothing else: {watched:?}");
}

/// THE CERTIFICATE IS FIRST, because it is the one the gauge and the
/// fingerprints speak for, and `serving_certificate` is what records it.
#[tokio::test]
async fn the_listener_certificate_is_the_one_the_gauge_speaks_for() {
    let mount = Mount::new(&generation("task"));
    let watched = inputs(&mount);
    assert_eq!(
        watched.watched().first(),
        Some(&mount.path("tls.pem").as_path())
    );
    assert_eq!(watched.not_after(Presented::Serving), Some(LEAF_NOT_AFTER));
}

/// EACH HALF CONTRIBUTES ON ITS OWN, and in THIS service nothing configured is
/// genuinely nothing to watch.
///
/// `iam` differs — its enrolment CA (D73) is watched too, and its chart ships a
/// default for it, so a cleartext `iam` still has a non-empty set. Here the
/// transport is the only security material read, so a cleartext deployment
/// watches nothing and `rotate::watch` idles for the life of the pod.
#[tokio::test]
async fn each_configured_half_contributes_on_its_own() {
    let mount = Mount::new(&generation("task"));

    assert!(
        Inputs::default().listener(None).upstream(None).is_empty(),
        "nothing configured is nothing to watch"
    );

    // TLS ON, NO CLIENT IDENTITY — the state a cut-over passes through, and the
    // one this car ships as the default. The listener and the CA bundle are
    // watched; nothing else is.
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
        Inputs::default().upstream(Some(&server_only)).watched(),
        vec![mount.path("ca.pem").as_path()],
        "an encrypted hop with no identity watches the bundle and nothing else"
    );

    // AND THE IDENTITY ON ITS OWN puts BOTH files in, which is the membership
    // this whole change turns on.
    assert_eq!(
        Inputs::default()
            .upstream(Some(&upstream_tls(&mount)))
            .watched(),
        vec![
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
        ],
        "the client certificate and its key both join the set"
    );
}
