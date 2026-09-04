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

use std::net::SocketAddr;

use yadgar_task::pb::yadgar::taskapi::v1::task_service_server::TaskServiceServer;
use yadgar_task::rotate;
use yadgar_task::serve::{self, ServeTls, LISTEN};
use yadgar_task::service::Task;
use yadgar_task::upstream::{self, UpstreamTls, TASK_DB};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let mut server = serve::builder(tls.as_ref()).map_err(|e| e.to_string())?;

    // THE BASELINE IS TAKEN HERE, BESIDE THE CODE THAT LOADED THE FILES, and
    // that is why the set is assembled as boot proceeds rather than at the end.
    // Deferring the first reading to the watcher's first poll would put the rest
    // of boot — the `task-db` dial — inside a window where a kubelet swap makes
    // the NEW file the baseline: the real rotation is then never noticed, and
    // the gauge describes a certificate the listener is not serving.
    let mut tls_inputs = rotate::Inputs::default().listener(tls.as_ref());

    // The HEADLESS Service name (D23). Resolving it yields every ready pod
    // address rather than one virtual IP.
    let db_host = env_or("TASK_DB_HOST", "task-db");
    // STRINGIFIED AND NAMED, for the same reason as every other error in this
    // function: `main` returns `Box<dyn Error>`, which Rust prints with DEBUG. A
    // bare `?` here yields `ParseIntError { kind: InvalidDigit }`, and the two
    // addresses below yield `AddrParseError(())` — a CrashLoop whose entire
    // output is `AddrParseError(())` tells an operator neither which variable was
    // wrong nor what it held. These three were the last bare `?`s left beside the
    // comments explaining why nothing else is one.
    let db_port: u16 = env_or("TASK_DB_PORT", "50051")
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

    // PARSED AT BOOT WHETHER OR NOT ANY TLS IS CONFIGURED. A value an operator
    // set and this binary cannot use is a mistake to refuse, not one to paper
    // over with a default nobody chose — and refusing it here means it is
    // refused on a cleartext deployment too, which is where it would otherwise
    // sit unnoticed until the cut-over.
    let schedule = rotate::Schedule::from_env().map_err(|e| e.to_string())?;
    let channel = upstream::connect(&db_host, db_port, db_tls.as_ref())
        .await
        // Same reasoning, and it matters more here: `BalanceError`'s messages
        // are paragraphs explaining that an empty bundle trusts nobody and that
        // a missing one is not a reason to connect in cleartext. Debug prints
        // the struct and throws all of that away.
        .map_err(|e| e.to_string())?;
    tracing::info!(
        reresolve_secs = yadgar_dial::reresolve_interval().as_secs(),
        tls = db_tls.is_some(),
        "connected to task-db"
    );

    // THE CA BUNDLE AND THE CLIENT IDENTITY TOGETHER (ADR-0516, ADR-0523). The
    // client certificate is read once inside `connect_tls`, out of a directory
    // mount that rotates, and an expired one STOPS this hop rather than merely
    // degrading it.
    tls_inputs = tls_inputs.upstream(db_tls.as_ref());

    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    // Named on the way out, for the reason given on TASK_DB_PORT above.
    let metrics_addr: SocketAddr = env_or("METRICS_LISTEN", "0.0.0.0:9090")
        .parse()
        .map_err(|e| format!("METRICS_LISTEN is not a host:port address: {e}"))?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    // AFTER THE EXPORTER, NEVER BEFORE IT. A value recorded before there is a
    // recorder is a value nobody ever sees.
    tls_inputs.export_not_after();

    // Named on the way out, for the reason given on TASK_DB_PORT above.
    let addr: SocketAddr = env_or("LISTEN", "0.0.0.0:50052")
        .parse()
        .map_err(|e| format!("LISTEN is not a host:port address: {e}"))?;

    // ARMED BEFORE THE SERVER IS SPAWNED, and that ordering is the fix rather
    // than an accident of where the line sits. `serve::shutdown` installs both
    // signal handlers when it is CALLED — a SIGTERM arriving between here and
    // the first poll of the future would otherwise take the process's default
    // disposition and kill it outright.
    let signals = serve::shutdown().map_err(|e| {
        format!("the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one")
    })?;

    tracing::info!(
        %addr,
        tls = tls.is_some(),
        watching = tls_inputs.watched().len(),
        rotation_poll_secs = schedule.poll().as_secs(),
        rotation_splay_max_secs = schedule.splay_max().as_secs(),
        drain_budget_secs = serve::DRAIN_BUDGET.as_secs(),
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
            () = rotate::watch(tls_inputs, schedule) => {}
        }
    };
    match serve::drain_within(serving, ask_to_stop, stop, serve::DRAIN_BUDGET).await {
        serve::Drain::Finished(result) => result?,
        serve::Drain::Overran => tracing::error!(
            budget_secs = serve::DRAIN_BUDGET.as_secs(),
            "the drain did not finish within its budget; ending anyway with calls still in \
             flight. A request blocked this long is the thing to look at"
        ),
    }

    Ok(())
}
