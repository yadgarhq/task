//! `serve`'s unit tests, in the submodule file Rust's own convention gives
//! them (`#[cfg(test)] mod tests;`) rather than inline in `serve.rs` — the
//! same split `src/upstream/tests.rs` made (ADR-0636's exemption is written
//! for exactly this layout).
//!
//! **THE DECISION ITSELF IS `yadgar-lifecycle`'s NOW (B-U5, ADR-0846)**, and
//! its own suite proves the full matrix. What is asserted HERE is this
//! repository's WIRING of it: that [`super::from_lookup`] reads the `LISTEN`
//! prefix and the `tls` chart key, so every refusal an operator reads names
//! the variable this binary is handed AND the value `chart/` renders it from.
//!
//! **STATIC ASSERTION MESSAGES.** No refusal's text is interpolated into an
//! assertion message: CodeQL's cleartext-logging query flags an `assert!`
//! that formats an error whose enum has Key/Certificate-named variants. The
//! `contains` checks carry the property; `cargo test` prints the values on
//! failure anyway.

use std::path::Path;

use super::*;

/// SENTINELS: nothing in `serve.rs` could produce any of them, so a test
/// that sees one saw it travel from the lookup.
const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/serving.crt";
const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/serving.key";
const SENTINEL_CA: &str = "/etc/yadgar/pangolin-7c21/client-ca.crt";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// A complete TLS listener with client auth `mode`, before any one key is
/// taken away by the case using it.
fn tls_with(mode: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ("LISTEN_TLS_CLIENT_AUTH", mode),
    ]
}

fn refusal(vars: &[(&'static str, &'static str)]) -> String {
    match from_lookup(lookup(vars)) {
        Ok(_) => panic!("this configuration must refuse the boot"),
        Err(error) => error.to_string(),
    }
}

/// NO UNCONFIGURED ANSWER (ADR-0845): an absent switch refuses, naming the
/// variable AND the chart key — the latter is what proves the wiring passes
/// `tls`, since the lifted type takes the chart key as an argument.
#[test]
fn absent_tls_enabled_is_refused_naming_the_variable_and_the_chart_key() {
    let message = refusal(&[("LISTEN_TLS_CLIENT_AUTH", "off")]);
    assert!(
        message.contains("LISTEN_TLS_ENABLED"),
        "the refusal must name the variable LISTEN_TLS_ENABLED"
    );
    assert!(
        message.contains("`tls.enabled`"),
        "the refusal must name the chart key tls.enabled"
    );
}

/// THE NEW REQUIRED KEY (ADR-0854, B-U5): an absent client-auth mode refuses,
/// with TLS on and with TLS off alike. Deleting the variable is a boot
/// refusal, never a way to turn verification off.
#[test]
fn absent_client_auth_is_refused_naming_the_variable_and_the_chart_key() {
    for enabled in ["1", "0"] {
        let vars = [
            ("LISTEN_TLS_ENABLED", enabled),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        let message = refusal(&vars);
        assert!(
            message.contains("LISTEN_TLS_CLIENT_AUTH"),
            "the refusal must name the variable LISTEN_TLS_CLIENT_AUTH"
        );
        assert!(
            message.contains("`tls.clientAuth`"),
            "the refusal must name the chart key tls.clientAuth"
        );
    }
}

/// EXACTLY `off`, `optional` or `required`. A nulled chart value renders
/// `""`; a permissive parse is how a typo becomes a posture.
#[test]
fn a_client_auth_outside_the_three_values_is_refused() {
    for value in ["", " ", "Off", "on", "true", "false", "none", "Required"] {
        let mut vars = tls_with("off");
        vars.retain(|(k, _)| *k != "LISTEN_TLS_CLIENT_AUTH");
        vars.push(("LISTEN_TLS_CLIENT_AUTH", value));
        let message = refusal(&vars);
        assert!(
            message.contains("LISTEN_TLS_CLIENT_AUTH") && message.contains("`tls.clientAuth`"),
            "an out-of-set client auth must be refused naming the variable and the chart key"
        );
    }
}

/// A verifying mode with no authority to verify against refuses, naming the
/// CA variable and the chart key that names its Secret.
#[test]
fn a_verifying_mode_without_a_client_ca_is_refused() {
    for mode in ["optional", "required"] {
        let message = refusal(&tls_with(mode));
        assert!(
            message.contains("LISTEN_TLS_CLIENT_CA_FILE"),
            "the refusal must name the variable LISTEN_TLS_CLIENT_CA_FILE"
        );
        assert!(
            message.contains("`tls.clientCaSecret`"),
            "the refusal must name the chart key tls.clientCaSecret"
        );
    }
}

/// A cleartext listener cannot verify a client certificate, so a verifying
/// mode beside `LISTEN_TLS_ENABLED=0` refuses rather than being ignored.
/// `off` beside it is the ordinary cleartext listener.
#[test]
fn a_verifying_mode_on_a_cleartext_listener_is_refused_and_off_is_not() {
    for mode in ["optional", "required"] {
        let vars = [
            ("LISTEN_TLS_ENABLED", "0"),
            ("LISTEN_TLS_CLIENT_AUTH", mode),
            ("LISTEN_TLS_CLIENT_CA_FILE", SENTINEL_CA),
        ];
        let message = refusal(&vars);
        assert!(
            message.contains("`tls.enabled`") && message.contains("`tls.clientAuth`"),
            "the refusal must name both chart keys"
        );
    }
    let off = [
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
    ];
    assert_eq!(from_lookup(lookup(&off)).unwrap(), None);
}

/// Every path reaches the settings, proved with names the module could not
/// have chosen for itself.
#[test]
fn the_certificate_the_key_and_the_client_ca_all_arrive() {
    let mut vars = tls_with("required");
    vars.push(("LISTEN_TLS_CLIENT_CA_FILE", SENTINEL_CA));
    let tls = from_lookup(lookup(&vars))
        .unwrap()
        .expect("a flag, a certificate and a key enable TLS");
    assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
    assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
    assert_eq!(tls.client_auth(), ClientAuth::Required);
    assert_eq!(tls.client_ca_file(), Some(Path::new(SENTINEL_CA)));
}

/// `off` verifies nothing, so a CA named beside it is neither read nor
/// watched: an adopter staging the CA Secret ahead of the flip must not
/// change what boots.
#[test]
fn off_drops_a_client_ca_named_beside_it() {
    let mut vars = tls_with("off");
    vars.push(("LISTEN_TLS_CLIENT_CA_FILE", SENTINEL_CA));
    let tls = from_lookup(lookup(&vars)).unwrap().expect("TLS is on");
    assert_eq!(tls.client_auth(), ClientAuth::Off);
    assert_eq!(tls.client_ca_file(), None);
}

/// The prefix is what selects the variables, so the upstream's transport
/// cannot configure the listener. `TASK_DB_TLS_*` is a real setting in this
/// process — [`crate::upstream`] reads it — which is what makes this worth
/// pinning rather than obvious.
#[test]
fn the_upstreams_variables_do_not_configure_the_listener() {
    let vars = [
        ("TASK_DB_TLS_ENABLED", "1"),
        ("TASK_DB_TLS_CA_FILE", SENTINEL_CERT),
        // The bare, unprefixed names: if the lookup reached them this would
        // be TLS with client auth `required`.
        ("TLS_ENABLED", "1"),
        ("TLS_CERT_FILE", SENTINEL_CERT),
        ("TLS_CLIENT_AUTH", "required"),
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
    ];
    assert_eq!(from_lookup(lookup(&vars)).unwrap(), None);
}
