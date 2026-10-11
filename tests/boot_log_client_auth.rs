//! The "task listening" line names which `ClientAuth` mode the listener is
//! running under (ledger 1422, mirroring task-db#87/db810a3).
//!
//! **WHY A SECOND CASE BESIDE `off`.** A test that only boots with
//! `LISTEN_TLS_CLIENT_AUTH=off` and asserts the field reads `"off"` stays
//! green even if `boot::serve_until_drained` hard-codes `ClientAuth::Off` —
//! the exact mutation `map_or(ClientAuth::Off, ..)` would collapse to if the
//! `Some` arm were ever dropped. [`a_verifying_listener_reports_its_own_mode`]
//! boots with `optional` instead, so the field can only read right if the
//! value actually came from the configured [`yadgar_task::serve::ServerTls`].
//!
//! **WHY THE REAL BINARY, THROUGH [`support::Booted`].** The field is written
//! by one `tracing::info!` call inside `serve_until_drained`, which a unit
//! test cannot reach — see `tests/support/mod.rs` for why the real binary runs
//! under `unshare -rm`. Parsing the line as JSON rather than substring
//! matching is the same argument tightened one step further: `contains("off")`
//! would also pass if the field were simply absent and some OTHER word on the
//! line happened to contain it.
//!
//! Certificates are minted per run, the same `rcgen` shape `tests/serve_tls.rs`
//! uses — a fixture key committed to the repository is a secret committed to
//! the repository.

mod support;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use support::{cleartext_env, Booted, BOOT_DEADLINE};

/// Parse the JSON line the binary wrote for its "task listening" event and
/// return the string value of `fields.<key>`, or fail naming what was there
/// instead.
fn field(line: &str, key: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("the \"task listening\" line was not JSON: {e}\n{line}"));
    value["fields"][key]
        .as_str()
        .unwrap_or_else(|| panic!("fields.{key} is not a JSON string in: {line}"))
        .to_string()
}

#[test]
fn a_cleartext_listener_reports_client_auth_off() {
    let mut task = Booted::start(&cleartext_env());
    let line = task.wait_for_line("the \"task listening\" line", BOOT_DEADLINE, |l| {
        l.contains("\"task listening\"")
    });
    assert_eq!(field(&line, "client_auth"), "off");
}

/// Mints a one-off CA and server certificate, the same shape
/// `tests/serve_tls.rs::pki` uses, trimmed to what a verifying boot needs: a
/// serving identity and a CA file to configure as `LISTEN_TLS_CLIENT_CA_FILE`.
/// No client leaf is minted — this test never dials the listener, it only
/// reads what the boot log says about the mode it was told to run.
struct Pki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-task boot-log test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &ca).unwrap();

    Pki {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A PEM file that deletes itself: [`support::Booted`] needs the listener's
/// identity and the client CA as PATHS, and this is the only shape a `TempPem`
/// is handed over in (D80).
struct TempPem(PathBuf);

fn run_id() -> u128 {
    static RUN: OnceLock<u128> = OnceLock::new();
    *RUN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    })
}

/// Unique by construction within this process — see `tests/serve_tls.rs`'s
/// `unique_name` for the measured reason a clock reading alone is not enough
/// (ledger 531).
fn unique_name() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "yadgar-task-boot-log-{}-{}-{}.pem",
        std::process::id(),
        run_id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

impl TempPem {
    fn with(contents: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name());
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{} already exists or cannot be made: {e}", path.display()));
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_verifying_listener_reports_its_own_mode() {
    let pki = pki("localhost");
    let cert = TempPem::with(&pki.cert_pem);
    let key = TempPem::with(&pki.key_pem);
    let ca = TempPem::with(&pki.ca_pem);

    let cert_path = cert.path().to_str().unwrap().to_string();
    let key_path = key.path().to_str().unwrap().to_string();
    let ca_path = ca.path().to_str().unwrap().to_string();

    // `cleartext_env` states `LISTEN_TLS_ENABLED=0` and `..CLIENT_AUTH=off`;
    // both are overridden below. `Booted::start` takes the last value for a
    // repeated key (`Command::envs` does), so appending the verifying values
    // after the cleartext ones is enough — every untouched key (`TASK_DB_*`,
    // `METRICS_LISTEN`) is kept exactly as the fixture states it.
    let mut vars: Vec<(&str, &str)> = cleartext_env();
    vars.extend([
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CLIENT_AUTH", "optional"),
        ("LISTEN_TLS_CERT_FILE", cert_path.as_str()),
        ("LISTEN_TLS_KEY_FILE", key_path.as_str()),
        ("LISTEN_TLS_CLIENT_CA_FILE", ca_path.as_str()),
    ]);

    let mut task = Booted::start(&vars);
    let line = task.wait_for_line("the \"task listening\" line", BOOT_DEADLINE, |l| {
        l.contains("\"task listening\"")
    });
    assert_eq!(field(&line, "client_auth"), "optional");
}
