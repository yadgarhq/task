//! The two stretches of boot that are not `main`'s wiring: installing the
//! logging subscriber, and running the server until it has drained.
//!
//! **A BINARY-ONLY MODULE, and that is the point of the file rather than an
//! accident of where it sits.** `lib.rs` does not declare it, so nothing here
//! joins `yadgar_task`'s public surface; `main.rs` reaches it as `mod boot;`
//! and the crate root's own `env_required` reaches back the other way.
//!
//! **WHY NOT IN `main.rs`.** Extracting into the same file would have taken
//! that file across the 500-line ceiling it passes today — an extraction only
//! ever adds lines to the file it lands in. Nor into `serve.rs`, which would
//! have needed a new `pub fn` on a published module to hold something no
//! caller outside this binary may use.
//!
//! Nothing here changed on the way over. Every line runs in the order it ran
//! in, including the order in which a misconfigured deployment is refused.

use std::net::SocketAddr;

use tonic::transport::{Channel, Server};
use yadgar_lifecycle::{drain_within, shutdown, Drain, DRAIN_BUDGET};
use yadgar_task::pb::yadgar::taskapi::v1::task_service_server::TaskServiceServer;
use yadgar_task::rotate::{self, Inputs, Schedule};
use yadgar_task::serve::ServeTls;
use yadgar_task::service::Task;

use crate::env_required;

/// The JSON subscriber, installed before anything else can want to log.
pub fn install_logging() {
    tracing_subscriber::fmt()
        .json()
        // A DEFAULT, because from_default_env() with RUST_LOG unset enables
        // NOTHING — the service runs silently and its boot sequence, its
        // capability probe result and its errors all vanish. Found by deploying:
        // two replicas were Running and `kubectl logs` returned nothing at all,
        // so the only way to see why one had restarted was the previous
        // container's exit output.
        //
        // A service nobody can observe is one D67 cannot measure either.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

/// EVERYTHING AFTER THE UPSTREAM CHANNEL EXISTS: the metrics exporter, the
/// listener, and the bounded drain.
///
/// One helper rather than several, because this is one stretch of a sequence
/// whose ORDER is the behaviour. The exporter is installed before the gauge
/// that feeds it, the signal handlers are armed before the server is spawned,
/// and the drain's budget starts when shutdown is requested. Cutting between
/// those steps would produce parts that cannot be read — or reordered — apart.
///
/// The two remaining `env_required` reads stay HERE, at the point in the
/// sequence they were always at, rather than moving up beside the others: a
/// deployment with a bad `METRICS_LISTEN` must still be refused where it was
/// refused before.
pub async fn serve_until_drained(
    mut server: Server,
    tls: Option<ServeTls>,
    channel: Channel,
    watch_inputs: Inputs,
    schedule: Schedule,
) -> Result<(), Box<dyn std::error::Error>> {
    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    // Named on the way out, for the reason given on TASK_DB_PORT above.
    let metrics_addr: SocketAddr = env_required("METRICS_LISTEN")?
        .parse()
        .map_err(|e| format!("METRICS_LISTEN is not a host:port address: {e}"))?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    // AFTER THE EXPORTER, NEVER BEFORE IT. A value recorded before there is a
    // recorder is a value nobody ever sees.
    watch_inputs.export_not_after();

    // Named on the way out, for the reason given on TASK_DB_PORT above.
    let addr: SocketAddr = env_required("LISTEN")?
        .parse()
        .map_err(|e| format!("LISTEN is not a host:port address: {e}"))?;

    // ARMED BEFORE THE SERVER IS SPAWNED, and that ordering is the fix rather
    // than an accident of where the line sits. `yadgar_lifecycle::shutdown`
    // installs both signal handlers when it is CALLED — a SIGTERM arriving between here and
    // the first poll of the future would otherwise take the process's default
    // disposition and kill it outright.
    let signals = shutdown().map_err(|e| {
        format!("the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one")
    })?;

    tracing::info!(
        %addr,
        tls = tls.is_some(),
        watching = watch_inputs.watched().len(),
        rotation_poll_secs = schedule.poll().as_secs(),
        rotation_splay_max_secs = schedule.splay_max().as_secs(),
        drain_budget_secs = DRAIN_BUDGET.as_secs(),
        "task listening"
    );

    // THE SERVER IS SPAWNED AND ASKED TO STOP THROUGH A CHANNEL, rather than
    // handed the shutdown future directly, because the drain has to be BOUNDED
    // and a budget's clock must start when shutdown is REQUESTED. A `timeout`
    // around the serving future itself would bound the server's whole life
    // instead, and end the process one budget after boot, on every boot.
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(
        server
            .add_service(TaskServiceServer::new(Task::new(channel)))
            .serve_with_shutdown(addr, async {
                let _ = stop_requested.await;
            }),
    );
    let stop = async {
        tokio::select! {
            () = signals => {}
            () = rotate::watch(watch_inputs, schedule) => {}
        }
    };
    match drain_within(serving, ask_to_stop, stop, DRAIN_BUDGET).await {
        Drain::Finished(result) => result?,
        Drain::Overran => tracing::error!(
            budget_secs = DRAIN_BUDGET.as_secs(),
            "the drain did not finish within its budget; ending anyway with calls still in \
             flight. A request blocked this long is the thing to look at"
        ),
    }

    Ok(())
}
