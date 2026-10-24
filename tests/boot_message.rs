//! What an operator reads when the boot refuses (ledger 1258).
//!
//! `main` used to return `Result<(), Box<dyn Error>>`, and Rust prints a `main`
//! that returns `Err` with DEBUG. Every refusal in `main.rs` was already
//! converted to its sentence, so it did not arrive as a variant name — it
//! arrived as a quoted, escaped string: `Error: "LISTEN_TLS_ENABLED is set but
//! …"`, every inner quote a `\"`. `main` now calls `run()` and prints
//! `Error: {e}` with Display. The unit tests in `src/` prove the sentences
//! exist; only running the BINARY proves they reach the operator as written.
//!
//! **The exit code is not what these tests discriminate.** An `Err` from
//! `main` exits 1 and so does `ExitCode::FAILURE`, so reverting to
//! `-> Result` turns the Display assertion red and leaves the exit code alone.

mod support;

use std::net::TcpListener;
use std::process::Command;

use support::{cleartext_env, run_to_exit, Booted, BIN, MARGIN};

/// The `Error: ` line from a refused boot, held to plain Display.
fn refusal_line(status: std::process::ExitStatus, stderr: &str) -> String {
    assert!(
        !status.success(),
        "a refused boot must exit non-zero: {status:?}"
    );
    let line = stderr
        .lines()
        .rfind(|l| l.starts_with("Error: "))
        .unwrap_or_else(|| panic!("no `Error: ` line on stderr: {stderr}"))
        .to_string();
    assert!(
        !line.starts_with("Error: \"") && !line.contains("\\\""),
        "the refusal was printed as a Debug string: {line}"
    );
    line
}

/// Run the binary directly, for refusals that come before `shared.yaml` is
/// read and so need no mount namespace.
fn refusal_without_mounts(vars: &[(&str, &str)]) -> String {
    let out = Command::new(BIN)
        .env_clear()
        .envs(vars.iter().copied())
        .output()
        .expect("the test rig could not start the binary");
    refusal_line(out.status, &String::from_utf8_lossy(&out.stderr))
}

/// A TYPED error: `ServeTlsError::NoServingFile`, the first refusal `run` can
/// reach with a complete mode. Debug of the error would print the variant
/// name; Debug of its sentence printed the sentence in quotes. Display prints
/// the sentence.
#[test]
fn a_typed_refusal_is_printed_as_its_sentence() {
    let line = refusal_without_mounts(&[
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
    ]);
    assert!(
        line.contains("LISTEN_TLS_ENABLED is \"1\" but LISTEN_TLS_CERT_FILE is not set"),
        "the refusal must name both variables: {line}"
    );
    assert!(
        !line.contains("NoServingFile"),
        "the operator got the Debug variant name, not the sentence: {line}"
    );
}

/// THE BINARY REFUSES AN ABSENT CLIENT-AUTH MODE (ADR-0854, B-U5), naming the
/// variable it reads and the chart value that renders it — through `main`,
/// not only through the library, so a `main` that read the listener with some
/// other chart key, or not through `serve::from_env` at all, turns this red.
#[test]
fn an_absent_client_auth_is_refused_naming_the_variable_and_the_chart_key() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN_TLS_CLIENT_AUTH");
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("LISTEN_TLS_CLIENT_AUTH is not set"),
        "the refusal must name the variable LISTEN_TLS_CLIENT_AUTH"
    );
    assert!(
        line.contains("`tls.clientAuth`"),
        "the refusal must name the chart key tls.clientAuth"
    );
}

/// A bare parse, named on the way out: the port is read before the shared
/// document, so this also needs no mount namespace.
#[test]
fn an_unparsable_db_port_names_the_variable() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "TASK_DB_PORT");
    vars.push(("TASK_DB_PORT", "abc"));
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("TASK_DB_PORT is not a port number"),
        "the refusal must name the variable: {line}"
    );
}

/// `LISTEN` is parsed after the shared document is read and the schedule is
/// resolved, so this boot needs the document mounted to get that far.
#[test]
fn an_unparsable_listen_names_the_variable() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN");
    vars.push(("LISTEN", "notanaddr"));
    let (status, stderr) = run_to_exit(&vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains("LISTEN is not a host:port address"),
        "the refusal must name the variable: {line}"
    );
    assert!(
        !line.contains("AddrParseError"),
        "the operator got the Debug of the parse error: {line}"
    );
}

/// A TRANSPORT failure rather than a misconfiguration (ledger 1333): `LISTEN`
/// names a real `host:port`, but another socket already holds it.
/// `boot::serve_until_drained` is the only place that can see this — the
/// bind happens inside `tokio::spawn`, after every env read has already
/// succeeded — and before ledger 1333 it let `result?` carry
/// `tonic::transport::Error` straight out, whose whole `Display` is the two
/// words "transport error": no LISTEN, no address, no OS reason.
///
/// **THE PROCESS EXITS ON ITS OWN, WITH NO SIGNAL SENT** (yaadgaar #313).
/// `yadgar_lifecycle::drain_within` returns `Drain::Finished(Err(..))` the
/// moment the serving task ends, so a bind that fails before any signal
/// arrives is a non-zero exit at once rather than a process that sits bound to
/// nothing until kubelet's liveness probe sends SIGTERM. This test sends no
/// signal: a lifecycle that awaited `stop` first leaves the process running,
/// and the exit wait below fails on its deadline, the harness's `MARGIN` (10 s).
/// Measured on the old pin (`v0.2.20`, with a 5 s bound at the time): red,
/// "waited 5s for the process to exit on its own after the bind failed; it was
/// still running".
///
/// Held in-process rather than by a second `unshare` child: the listener and
/// the binary under test must share one network namespace for the collision
/// to be real, and `unshare -rm` only ever isolates the mount namespace
/// (`-m`), never the network one, so a plain `TcpListener` here collides with
/// the child exactly as a second pod on the same node would.
#[test]
fn a_bind_failure_names_the_listen_address() {
    let holder = TcpListener::bind("127.0.0.1:0").expect("a free port must be available to hold");
    let addr = holder
        .local_addr()
        .expect("a bound listener has an address");
    let listen = addr.to_string();

    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN");
    vars.push(("LISTEN", listen.as_str()));

    let mut task = Booted::start(&vars);
    // Fires regardless of whether the real bind that follows succeeds — see
    // `serve_until_drained`, which logs it before spawning the server task.
    task.wait_until_listening();
    let status = task.wait_for_exit("on its own after the bind failed", MARGIN);
    let seen = task.seen().join("\n");
    drop(holder);

    let line = refusal_line(status, &seen);
    assert!(
        line.contains(&format!(
            "the gRPC server on LISTEN={listen} stopped with an error"
        )),
        "the refusal must name the LISTEN address: {line}"
    );
    assert!(
        line.contains("Address already in use"),
        "the refusal must carry the OS reason, not just tonic's own `transport error`: {line}"
    );
}

/// ADR-0925 Q-C1: `TASK_DB_REQUEST_TIMEOUT_SECONDS` has no compiled-in default, so
/// each of these four values refuses the boot, naming the variable AND the
/// chart key that renders it. Read before `shared.yaml`, so no mount namespace.
#[test]
fn a_missing_or_out_of_range_request_timeout_names_the_variable_and_the_chart_key() {
    for bad in [None, Some("0"), Some("13"), Some("60")] {
        let mut vars = cleartext_env();
        vars.retain(|(k, _)| *k != "TASK_DB_REQUEST_TIMEOUT_SECONDS");
        if let Some(value) = bad {
            vars.push(("TASK_DB_REQUEST_TIMEOUT_SECONDS", value));
        }
        let line = refusal_without_mounts(&vars);
        assert!(
            line.contains("TASK_DB_REQUEST_TIMEOUT_SECONDS"),
            "{bad:?}: the refusal must name the variable: {line}"
        );
        assert!(
            line.contains("taskDb.requestTimeoutSeconds"),
            "{bad:?}: the refusal must name the chart key: {line}"
        );
    }
}

/// ADR-1006: the listener's four protocol limits have no compiled-in default
/// (ADR-0569), so an absent one refuses the boot, naming the variable AND the
/// `server.limits` chart value that renders it — through `main`, so a `main`
/// that never read them, or read them under another prefix or chart key, turns
/// this red. Read beside `serve::from_env`, before `shared.yaml`, so no mount
/// namespace.
#[test]
fn an_absent_server_limit_is_refused_naming_the_variable_and_the_chart_key() {
    for (var, chart) in [
        (
            "LISTEN_MAX_CONCURRENT_STREAMS",
            "server.limits.maxConcurrentStreams",
        ),
        (
            "LISTEN_KEEPALIVE_INTERVAL_SECS",
            "server.limits.keepaliveIntervalSeconds",
        ),
        (
            "LISTEN_KEEPALIVE_TIMEOUT_SECS",
            "server.limits.keepaliveTimeoutSeconds",
        ),
        (
            "LISTEN_MAX_HEADER_LIST_BYTES",
            "server.limits.maxHeaderListBytes",
        ),
    ] {
        let mut vars = cleartext_env();
        vars.retain(|(k, _)| *k != var);
        let line = refusal_without_mounts(&vars);
        assert!(
            line.contains(&format!("{var} is not set")),
            "{var}: the refusal must name the variable: {line}"
        );
        assert!(
            line.contains(&format!("`{chart}`")),
            "{var}: the refusal must name the chart value {chart}: {line}"
        );
    }
}
