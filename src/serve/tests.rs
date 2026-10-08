//! `serve`'s unit tests, in the submodule file Rust's own convention gives
//! them (`#[cfg(test)] mod tests;`) rather than inline in `serve.rs` — the
//! same split `src/upstream/tests.rs` made and for the same reason: the
//! three review rounds of ADR-0845 coverage pushed `serve.rs` over the
//! 500-line file ceiling with no seam in its 300-odd lines of production
//! code, so cutting it in two to satisfy the number would have been a split
//! made for the wrong reason (ADR-0636's exemption is written for exactly
//! this layout).
//!
//! Nothing here changed on the way over except the indentation: `use
//! super::*;` reaches the same items from a child module that it reached
//! from an inline one.

use super::*;

/// SENTINELS: nothing in `serve.rs` could produce either of them, so a test
/// that sees one saw it travel from the lookup.
const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/serving.crt";
const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/serving.key";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// NO UNCONFIGURED ANSWER ANY MORE (ADR-0845). The compiled-in default
/// this used to fall back to is deleted: absent is refused exactly like
/// any other value outside "1"/"0", naming the knob.
#[test]
fn absent_tls_enabled_is_refused() {
    let error = ServeTls::from_lookup(LISTEN, lookup(&[])).unwrap_err();
    assert!(matches!(
        error,
        ServeTlsError::EnabledNotBoolean("LISTEN", _)
    ));
    let message = error.to_string();
    // The refusal's own text is not interpolated into the assertion
    // message (CodeQL's cleartext-logging query flags that shape): the
    // assertion already fails loudly enough naming what was expected,
    // and `cargo test`'s own failure output prints `error`/`message` in
    // full regardless.
    assert!(
        message.contains("LISTEN_TLS_ENABLED"),
        "the refusal must name the variable LISTEN_TLS_ENABLED"
    );
    assert!(
        message.contains("tls.enabled"),
        "the refusal must name the chart key tls.enabled"
    );
}

/// AN EMPTY VALUE IS NAMED DIFFERENTLY FROM AN ABSENT ONE, the same
/// discrimination `env_required` makes in `main.rs`: a nulled chart
/// value renders `""`, which is what an operator is most likely to hit.
#[test]
fn an_empty_tls_enabled_is_refused_and_named_differently_from_absent() {
    let empty = ServeTls::from_lookup(LISTEN, lookup(&[("LISTEN_TLS_ENABLED", "")]))
        .unwrap_err()
        .to_string();
    let absent = ServeTls::from_lookup(LISTEN, lookup(&[]))
        .unwrap_err()
        .to_string();
    assert!(
        empty.contains("(empty)"),
        "the refusal must say the value was empty"
    );
    assert_ne!(empty, absent, "empty and absent must not share one message");
}

/// THE REVERTED STATE is now `"0"` WRITTEN EXPLICITLY, not absence. A
/// certificate left mounted while the flag is off is still legitimate —
/// that is how the cut-over gets reverted — so it must not become an
/// error on its own.
#[test]
fn a_certificate_alone_with_the_flag_explicitly_off_does_not_enable_tls() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert_eq!(ServeTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
}

/// Exactly "0" is off; every OTHER value — including the ones a permissive
/// parse used to collapse into off — refuses rather than silently serving
/// cleartext under a value nobody chose it to mean (ADR-0845).
#[test]
fn anything_but_zero_or_one_is_refused() {
    for value in ["false", "no", "true", "yes", "2", "", " "] {
        let vars = [
            ("LISTEN_TLS_ENABLED", value),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        assert!(
            matches!(
                ServeTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServeTlsError::EnabledNotBoolean("LISTEN", _))
            ),
            "{value:?} must be refused, not treated as off"
        );
    }
}

/// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no
/// certificate is a deployment mistake, and the answer to it is an error
/// rather than a plaintext listener.
#[test]
fn asking_for_tls_without_a_certificate_is_an_error() {
    for vars in [
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ],
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", ""),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ],
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", "   "),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ],
    ] {
        assert!(
            matches!(
                ServeTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServeTlsError::NoCertFile("LISTEN"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// The same for the key. Half a pair is not an identity, and the message
/// has to name the half that is missing.
#[test]
fn asking_for_tls_without_a_private_key_is_an_error() {
    for vars in [
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ],
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", "   "),
        ],
    ] {
        assert!(
            matches!(
                ServeTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServeTlsError::NoKeyFile("LISTEN"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// Both paths reach the settings, proved with names the module could not
/// have chosen for itself.
#[test]
fn the_certificate_and_the_key_both_arrive() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    let tls = ServeTls::from_lookup(LISTEN, lookup(&vars))
        .unwrap()
        .expect("a flag, a certificate and a key enable TLS");
    assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
    assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
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
        // The bare, unprefixed names: not `LISTEN_TLS_ENABLED`, so if the
        // lookup reached them this would be TLS. `LISTEN_TLS_ENABLED`
        // itself is stated explicitly below — ADR-0845 leaves it no
        // default to fall into — so this proves isolation under "0"
        // rather than under absence.
        ("TLS_ENABLED", "1"),
        ("TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_ENABLED", "0"),
    ];
    assert_eq!(ServeTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
}
