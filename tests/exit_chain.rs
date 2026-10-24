//! THE EXIT CHAIN, held at the binary (ledger 748): the two ways a running
//! `task` is asked to stop both end the process with exit code 0, and a call
//! in flight when SIGTERM arrives still gets its answer (yaadgaar #318).
//!
//! **THE IN-FLIGHT CASE IS THE ONLY ONE THAT SEES THE DRAIN.** Replacing
//! `drain_within` in `src/boot.rs` with `stop.await; serving.abort();` keeps
//! both exit-code cases below green, because an aborted server still lets
//! `main` return `Ok` and exit 0. Measured with that mutant applied:
//! [`sigterm_lets_an_in_flight_call_finish`] is red, and the two cases below
//! stay green. The client's call ends in a reset instead of `Ok`: "the call in
//! flight at SIGTERM must get its answer, got: Err(Status { code: Unknown,
//! message: "transport error", source: Some(tonic::transport::Error(Transport,
//! hyper::Error(Io, Kind(ConnectionReset)))) })" (measured 2026-10-24). It is
//! green with the real drain. `yadgar-lifecycle`'s own `tests/shutdown.rs`
//! holds no request in flight, so this case is the estate's in-flight canary.
//!
//! The library tests prove the parts — `yadgar-lifecycle` that a signal resolves
//! `shutdown()` and that a changed file resolves `rotate::watch`,
//! `tests/assembly.rs` that the watch set holds the right files. None of them
//! can see `boot::serve_until_drained` wiring those futures into the `select!`
//! that stops the server. Deleting either arm compiled and passed every suite
//! here. Only running the binary can tell.
//!
//! **What each case kills, measured by mutating `src/boot.rs`:**
//!
//! - Delete the `shutdown()` binding AND its `select!` arm: no handler is ever
//!   installed, SIGTERM takes the kernel default, the status carries signal 15
//!   and no code, and [`sigterm_drains_and_exits_zero`]'s `Some(0)` is red.
//! - Delete the arm ONLY: the handler is installed when `shutdown()` is CALLED
//!   and tokio never removes it, so SIGTERM is swallowed and the server keeps
//!   serving. The exit wait's deadline fires; the test kills the child and fails.
//! - Delete the rotation arm: nothing polls the watcher, so
//!   [`a_rewritten_shared_document_drains_and_exits_zero`] never sees the
//!   CHANGED line and fails on its deadline.
//!
//! A failing drain is NOT one of these cases. `Drain::Overran` exits 0 by
//! design and `Drain::Finished(Err)` exits 1 under either shape of `main`, so
//! nothing about the drain's own outcome moves the code this file asserts.
//!
//! See `tests/support/mod.rs` for why each run is in its own mount namespace.

mod support;

use std::os::unix::process::ExitStatusExt;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use support::{cleartext_env, describe, Booted, FIXTURE, MARGIN, POLL, SPLAY_MAX};
use tokio::sync::Notify;
use tonic::{Request, Response, Status};
use yadgar_lifecycle::DRAIN_BUDGET;
use yadgar_task::pb::yadgar::task::v1 as db;
use yadgar_task::pb::yadgar::task::v1::task_db_service_server::{
    TaskDbService, TaskDbServiceServer,
};
use yadgar_task::pb::yadgar::taskapi::v1 as api;
use yadgar_task::pb::yadgar::taskapi::v1::task_service_client::TaskServiceClient;

/// Case (i): kubelet's SIGTERM ends the process with 0.
///
/// The deadline is the drain's whole budget plus a margin, not less: an
/// `Overran` drain is a legal exit 0 that arrives one budget after the signal.
#[test]
fn sigterm_drains_and_exits_zero() {
    let mut task = Booted::start(&cleartext_env());
    task.wait_until_listening();

    task.terminate();
    let status = task.wait_for_exit("after SIGTERM", DRAIN_BUDGET + MARGIN);

    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must drain and exit 0 ({}); signal 15 here means no handler was \
         installed",
        describe(Some(status))
    );
    assert_eq!(status.signal(), None);
    assert!(
        task.seen()
            .iter()
            .any(|l| l.contains("draining in-flight requests") && l.contains("SIGTERM")),
        "the drain must name the signal that started it"
    );
}

/// Case (ii): a rewritten watched file ends the process with 0.
///
/// `shared.yaml` is the one watched file a cleartext deployment has. The
/// rewrite keeps the schedule valid and changes the bytes, which is all the
/// watcher compares.
#[test]
fn a_rewritten_shared_document_drains_and_exits_zero() {
    let mut task = Booted::start(&cleartext_env());
    task.wait_until_listening();

    task.rewrite_shared(&format!("{FIXTURE}# rotated by tests/exit_chain.rs\n"));
    // One poll to notice, the splay, then the drain's whole budget.
    let deadline = POLL + SPLAY_MAX + DRAIN_BUDGET + MARGIN;
    let started = std::time::Instant::now();

    let changed = task.wait_for_line("the watcher's CHANGED line", deadline, |l| {
        l.contains("have CHANGED on disk")
    });
    assert!(
        changed.contains("shared.yaml"),
        "the CHANGED line must name the file that changed: {changed}"
    );
    // TLS is off, so both fingerprints are reported, and reported as `none`.
    for field in [
        "\"serving_before\":\"none\"",
        "\"serving_after\":\"none\"",
        "\"client_before\":\"none\"",
        "\"client_after\":\"none\"",
    ] {
        assert!(
            changed.contains(field),
            "the CHANGED line must carry {field}: {changed}"
        );
    }

    let status = task.wait_for_exit(
        "after the watched file changed",
        deadline.saturating_sub(started.elapsed()),
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a rotation is not an error; it must drain and exit 0 ({})",
        describe(Some(status))
    );
}

/// Case (iii): a call in flight when SIGTERM arrives is answered, and the
/// process still exits 0 (yaadgaar #318).
///
/// A stub `task-db` serves on loopback. Its `ListTasks` — the call behind
/// `FindTasks` — reports that it arrived, then waits to be released. The test
/// sends `FindTasks` to the real binary, waits for the stub's arrival signal,
/// sends SIGTERM, waits 300 ms (the one sleep here: the gap in which an
/// aborted server would already have dropped the call), then releases the
/// stub. The drain must hold the call open across that gap and deliver the
/// answer.
///
/// MUTATION, measured: `stop.await; serving.abort();` in place of the
/// `drain_within` match in `src/boot.rs` turns this red on the `Ok` assertion
/// below (a `ConnectionReset`; the file header quotes it), while both cases
/// above stay green.
#[test]
fn sigterm_lets_an_in_flight_call_finish() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    let stub = rt.block_on(HeldStore::serve());

    let listen = free_loopback_port();
    let db_port = stub.port.to_string();
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN" && *k != "TASK_DB_PORT");
    vars.push(("LISTEN", listen.as_str()));
    vars.push(("TASK_DB_PORT", db_port.as_str()));

    let mut task = Booted::start(&vars);
    task.wait_until_listening();
    let mut client = rt.block_on(connect(&listen));

    let call = rt.spawn(async move {
        client
            .find_tasks(api::FindTasksRequest::default())
            .await
            .map(Response::into_inner)
    });
    if stub.arrived.recv_timeout(MARGIN).is_err() {
        task.fail("the stub task-db never saw the FindTasks call arrive");
    }

    task.terminate();
    std::thread::sleep(Duration::from_millis(300));
    stub.release.notify_one();

    let answer = rt
        .block_on(async { tokio::time::timeout(MARGIN, call).await })
        .expect("the call in flight at SIGTERM must end within the margin")
        .expect("the client task must not panic");
    assert!(
        answer.is_ok(),
        "the call in flight at SIGTERM must get its answer, got: {answer:?}"
    );

    let status = task.wait_for_exit("after draining the in-flight call", MARGIN);
    assert_eq!(
        status.code(),
        Some(0),
        "a drain that answered its in-flight call must exit 0 ({})",
        describe(Some(status))
    );
}

/// A loopback address with a port nothing holds right now. `LISTEN` must be a
/// concrete port so the test can dial it: the "task listening" line logs the
/// address as configured, so port 0 would leave the test nothing to dial. The
/// port is released before the binary binds it, a window another process could
/// take it in; on a loopback test host that window has not been seen to close.
fn free_loopback_port() -> String {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
    probe
        .local_addr()
        .expect("a bound listener has an address")
        .to_string()
}

/// Dial the binary until it accepts. "task listening" is logged before the
/// spawned server binds, so the first dial can race the bind; a refused dial is
/// retried, and the readiness signal is the dial that succeeds.
async fn connect(listen: &str) -> TaskServiceClient<tonic::transport::Channel> {
    let until = Instant::now() + MARGIN;
    loop {
        match TaskServiceClient::connect(format!("http://{listen}")).await {
            Ok(client) => return client,
            Err(e) if Instant::now() >= until => {
                panic!("task never accepted a connection on {listen}: {e}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

/// The stub `task-db`: `ListTasks` signals its arrival and blocks until the
/// test releases it. Every other RPC is `Unimplemented`; none is called.
struct HeldStore {
    port: u16,
    arrived: mpsc::Receiver<()>,
    release: Arc<Notify>,
}

struct HeldHandler {
    arrived: mpsc::Sender<()>,
    release: Arc<Notify>,
}

impl HeldStore {
    /// Bind first, then serve the bound listener, so no other process can take
    /// the port between the two.
    async fn serve() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port for the stub task-db");
        let port = listener.local_addr().expect("the bound address").port();
        let (tx, arrived) = mpsc::channel();
        // `notify_one` stores a permit when nobody is waiting yet, so a release
        // that races the handler's `notified()` is not lost.
        let release = Arc::new(Notify::new());
        let handler = HeldHandler {
            arrived: tx,
            release: release.clone(),
        };
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(TaskDbServiceServer::new(handler))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await;
        });
        Self {
            port,
            arrived,
            release,
        }
    }
}

fn unused<T>(rpc: &str) -> Result<Response<T>, Status> {
    Err(Status::unimplemented(format!(
        "the stub task-db does not serve {rpc}"
    )))
}

#[tonic::async_trait]
impl TaskDbService for HeldHandler {
    async fn create_task(
        &self,
        _: Request<db::CreateTaskRequest>,
    ) -> Result<Response<db::CreateTaskResponse>, Status> {
        unused("CreateTask")
    }

    async fn update_task(
        &self,
        _: Request<db::UpdateTaskRequest>,
    ) -> Result<Response<db::UpdateTaskResponse>, Status> {
        unused("UpdateTask")
    }

    async fn get_task(
        &self,
        _: Request<db::GetTaskRequest>,
    ) -> Result<Response<db::GetTaskResponse>, Status> {
        unused("GetTask")
    }

    async fn list_tasks(
        &self,
        _: Request<db::ListTasksRequest>,
    ) -> Result<Response<db::ListTasksResponse>, Status> {
        let _ = self.arrived.send(());
        self.release.notified().await;
        Ok(Response::new(db::ListTasksResponse::default()))
    }

    async fn delete_task(
        &self,
        _: Request<db::DeleteTaskRequest>,
    ) -> Result<Response<db::DeleteTaskResponse>, Status> {
        unused("DeleteTask")
    }
}
