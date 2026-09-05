//! What this process does when the certificate it is serving is replaced
//! underneath it — and, now, WHICH FILES this service puts in front of the
//! watcher that does it.
//!
//! **The watcher itself moved out.** `Schedule`, `Inputs`, `Presented`, `watch`
//! and the `yadgar_tls_certificate_not_after_seconds` gauge live in
//! [`yadgar_lifecycle::rotate`], pinned by tag per ADR-0526. This file was a
//! near-byte-identical copy of `iam/src/rotate.rs`, with `gateway` carrying a
//! third, exactly as ADR-0523 said it would be — *"the watcher core is
//! repo-agnostic and is about to exist in four copies; lift it into a shared
//! crate before the third."* What is left here is the half that is genuinely
//! this service's: which of its own configuration types read files at boot, and
//! which files each one read.
//!
//! # The ruling: exit on change
//!
//! Serving certificates are read ONCE, when the listener is built.
//! [`crate::serve::builder`] hands tonic an acceptor holding an
//! `Arc<ServerConfig>` built there and then, and nothing afterwards can swap it.
//! So a pod started today serves its day-0 leaf until it restarts, whatever
//! cert-manager writes into the Secret in the meantime. The chart mounts those
//! Secrets as DIRECTORIES rather than with `subPath`, deliberately, so kubelet
//! does refresh the files inside the pod. Only the process never re-reads them.
//!
//! [`yadgar_lifecycle::rotate::watch`] polls a digest of every file in
//! [`watch_set`], logs which one changed, waits out a per-pod splay, and ends.
//! The caller selects on that, drains, and returns `Ok(())`. **A change is not
//! an error, so the exit code is 0.**
//!
//! **THE CLIENT CERTIFICATE IS THE MEMBER WITH THE WORST FAILURE.** ADR-0516
//! records that an expired CLIENT leaf STOPS a hop rather than degrading it, so
//! a process that read it once and never again keeps serving perfectly and
//! stops being able to reach its own store — on a date, with nothing having
//! warned. The serving leaf is the milder case this module was written for.
//!
//! # WHY THE SET IS A FUNCTION AND NOT A RUN OF STATEMENTS IN `main`
//!
//! It used to be two builder calls in `main.rs`, forty lines apart. No test in
//! this repository spawns the binary, so deleting either of them compiled,
//! passed the whole suite, and shipped a process that would never notice that
//! file rotating. `tests/tls_rotation.rs` could not catch it either: it rebuilt
//! the same assembly by hand, so `main.rs` and the test could disagree while
//! both stayed green.
//!
//! [`watch_set`] is the one expression that names this service's material, and
//! `main.rs` calls it rather than repeating it. `tests/assembly.rs` calls the
//! SAME function, so deleting a member from the list below turns a test red.

pub use yadgar_lifecycle::rotate::{
    watch, Configuration, File, Inputs, Material, Presented, Schedule, ScheduleError,
    CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};

use crate::serve::ServeTls;
use crate::upstream::UpstreamTls;

/// The `service` label on [`CERTIFICATE_NOT_AFTER`], and the name in the
/// watcher's log lines.
///
/// A module constant here, where `iam` reads `crate::service::SERVICE`. That is
/// a difference of where the name is kept, never of what it is: a dashboard
/// selects on this string.
const SERVICE: &str = "task";

/// The listener's certificate and the private key belonging to it.
///
/// **Both halves, or the pair rotates half-watched.** kubelet swaps a mount
/// atomically, so a set holding only the certificate still fires on an ordinary
/// rotation — but a deployment that rewrites the key alone would pass
/// unnoticed, and so would an implementation that named the certificate twice.
impl Material for ServeTls {
    fn files(&self) -> Vec<File<'_>> {
        vec![
            File::certificate(Presented::Serving, self.cert_file()),
            File::read(self.key_file()),
        ]
    }
}

/// The CA bundle `task-db`'s certificate is verified against, AND the client
/// certificate this service presents to it.
///
/// **BOTH HALVES, and the second one is the load-bearing member.** The client
/// certificate and its key are read once in `yadgar_dial::TlsOptions::prepare`,
/// out of a directory mount that rotates. Left out of the set, this process
/// works perfectly until that leaf expires and then fails hard, with no exit, no
/// gauge movement and no log.
///
/// The identity is `Some`/`Some` or `None`/`None` and cannot be half of one:
/// [`crate::upstream::UpstreamTls`] refuses a certificate without its key at
/// boot, so there is no half-configured arm to handle here.
impl Material for UpstreamTls {
    fn files(&self) -> Vec<File<'_>> {
        let mut files = vec![File::read(self.ca_file())];
        if let (Some(certificate), Some(key)) =
            (self.client_certificate_file(), self.client_key_file())
        {
            files.push(File::certificate(Presented::Client, certificate));
            files.push(File::read(key));
        }
        files
    }
}

/// Everything this deployment read at boot, hashed as it was read.
///
/// **THE LIST IS THE ASSERTION.** A service lists what it HAS. TLS is opt-in at
/// both ends here and off by default, and `Option<M>: Material` folds an absent
/// one to nothing, so neither TLS argument needs a branch.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS THE THIRD MEMBER, AND IT IS NOT
/// OPTIONAL (step 2a).** `config` is `shared/shared.yaml`, mounted from
/// `yadgarhq/config`'s `shared` ConfigMap, and it is a [`Material`] like the
/// other two: `Configuration` implements the trait by returning the one file it
/// read its schedule from (`yadgar_lifecycle::rotate::Configuration::files`), so
/// folding it in here joins the document to the ADR-0523 watch set through the
/// same `Inputs::also` path the listener and the upstream identity already take.
/// Unlike them it takes `&Configuration` rather than `Option<&Configuration>`
/// and is folded LAST — every deployment mounts it, so a watch set with neither
/// TLS setting configured is no longer empty the way `each_configured_half_
/// contributes_on_its_own` used to assert: an operator editing `shared.yaml`
/// restarts this pod exactly as editing a certificate would.
///
/// Called from `main.rs` INSIDE boot, beside the code that read these files:
/// every entry is hashed as it is added, so the baseline is the bytes the
/// process actually loaded. Collecting paths and reading them when the watcher
/// first polls would put the rest of boot inside a window where a kubelet swap
/// quietly becomes the baseline, and the real rotation would never be noticed.
pub fn watch_set(
    listener: Option<&ServeTls>,
    upstream: Option<&UpstreamTls>,
    config: &Configuration,
) -> Inputs {
    Inputs::of(SERVICE, &[&listener, &upstream, config])
}
