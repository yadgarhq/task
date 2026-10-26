//! The chart's `server.limits` block is bounded by the `yadgar-lifecycle` this
//! binary pins, and this is where that bound stops being a comment (ADR-1006).
//!
//! `yadgar_lifecycle::serve_tls::ServerLimits` owns the RANGE each listener
//! limit must sit in, and refuses a boot outside it; the DEFAULT lives only in
//! `chart/values.yaml` (ADR-0569, ADR-0705). `chart/values.schema.json` states
//! the same ranges as `minimum` and `maximum`. Nothing else holds the three
//! together: bump the pin to a lifecycle that narrows a range, and the chart
//! would admit a value the binary refuses at boot. This test reds on that bump.
//!
//! Every default is also pinned by a LITERAL (ADR-0599), so a change to the
//! ruled numbers is a deliberate edit here, not a silent drift.

use std::ops::RangeInclusive;
use std::path::PathBuf;

use serde_json::Value;
use yadgar_lifecycle::serve_tls::ServerLimits;

/// Each leaf under `server.limits`, its ADR-1006 default, the library's range,
/// and the variable `templates/deployment.yaml` renders it into.
const LIMITS: [(&str, u64, RangeInclusive<u64>, &str); 4] = [
    (
        "maxConcurrentStreams",
        256,
        ServerLimits::MAX_CONCURRENT_STREAMS,
        "LISTEN_MAX_CONCURRENT_STREAMS",
    ),
    (
        "keepaliveIntervalSeconds",
        30,
        ServerLimits::KEEPALIVE_INTERVAL_SECS,
        "LISTEN_KEEPALIVE_INTERVAL_SECS",
    ),
    (
        "keepaliveTimeoutSeconds",
        10,
        ServerLimits::KEEPALIVE_TIMEOUT_SECS,
        "LISTEN_KEEPALIVE_TIMEOUT_SECS",
    ),
    (
        "maxHeaderListBytes",
        16384,
        ServerLimits::MAX_HEADER_LIST_BYTES,
        "LISTEN_MAX_HEADER_LIST_BYTES",
    ),
];

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()))
}

/// The value of `server.limits.<leaf>` in `chart/values.yaml`.
///
/// ANCHORED AT THE INDENT the block uses, so a key NAMED in a comment, or the
/// same key under another block, cannot match. A missing key panics rather than
/// defaulting, so deleting the default reddens this test.
fn values_default(leaf: &str) -> u64 {
    let values = read("chart/values.yaml");
    let mut block: Vec<&str> = Vec::new();
    let mut found = Vec::new();
    for line in values.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let depth = (line.len() - trimmed.len()) / 2;
        block.truncate(depth);
        let key = trimmed.split(':').next().unwrap_or_default();
        if block == ["server", "limits"] && key == leaf {
            let value = trimmed[key.len() + 1..]
                .split('#')
                .next()
                .unwrap_or_default();
            found.push(value.trim().to_string());
        }
        if trimmed.ends_with(':') {
            block.push(key);
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected one `server.limits.{leaf}`, got {found:?}"
    );
    found[0]
        .parse()
        .unwrap_or_else(|why| panic!("`server.limits.{leaf}` is not an integer: {why}"))
}

fn schema_limits() -> Value {
    let schema: Value = serde_json::from_str(&read("chart/values.schema.json"))
        .expect("chart/values.schema.json must be valid JSON");
    let block = schema["properties"]["server"]["properties"]["limits"].clone();
    assert!(block.is_object(), "the schema has no `server.limits` block");
    block
}

#[test]
fn the_chart_defaults_are_the_ruled_ones_and_inside_the_library_ranges() {
    for (leaf, ruled, range, _) in LIMITS {
        let default = values_default(leaf);
        assert_eq!(
            default, ruled,
            "`server.limits.{leaf}` moved off its ADR-1006 default"
        );
        assert!(
            range.contains(&default),
            "`server.limits.{leaf}` = {default} is outside {range:?}, which the pinned \
             yadgar-lifecycle refuses at boot"
        );
    }
    assert!(
        values_default("keepaliveTimeoutSeconds") < values_default("keepaliveIntervalSeconds"),
        "the keepalive timeout must sit below the interval, or the library refuses the boot"
    );
}

#[test]
fn the_schema_bounds_are_the_library_ranges_and_every_key_is_required() {
    let block = schema_limits();
    let required = block["required"]
        .as_array()
        .expect("`server.limits` must list its keys under `required`");
    for (leaf, _, range, _) in LIMITS {
        let property = &block["properties"][leaf];
        assert_eq!(property["type"], "integer", "server.limits.{leaf}");
        assert_eq!(
            property["minimum"].as_u64(),
            Some(*range.start()),
            "the schema's minimum for `server.limits.{leaf}` is not the pinned library's"
        );
        assert_eq!(
            property["maximum"].as_u64(),
            Some(*range.end()),
            "the schema's maximum for `server.limits.{leaf}` is not the pinned library's"
        );
        assert!(
            required.iter().any(|k| k == leaf),
            "`server.limits.{leaf}` must be `required`: the binary has no default (ADR-0569)"
        );
    }
}

/// `templates/deployment.yaml` binds `$limits` to `.Values.server.limits` once,
/// behind a `kindIs "map"` guard, so a nulled block reaches the named refusal in
/// `templates/render-checks.yaml` instead of a raw nil-pointer error. Each
/// variable is rendered `| int`: helm hands a values-file number over as a
/// float64, and `quote` alone prints `1048576` as `1.048576e+06`, which the
/// binary refuses as not a whole number.
#[test]
fn the_deployment_renders_each_variable_from_its_chart_key() {
    let deployment = read("chart/templates/deployment.yaml");
    assert!(
        deployment.contains("$limits := ")
            && deployment.contains("(kindIs \"map\" .Values.server.limits) .Values.server.limits"),
        "deployment.yaml must bind `$limits` to `.Values.server.limits` behind a map guard"
    );
    for (leaf, _, _, var) in LIMITS {
        let at = deployment
            .find(&format!("- name: {var}"))
            .unwrap_or_else(|| panic!("deployment.yaml must render {var}"));
        let next: String = deployment[at..]
            .lines()
            .take(2)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            next.contains(&format!("$limits.{leaf} | int64 | quote")),
            "{var} is not rendered from `server.limits.{leaf}` as an integer: {next}"
        );
    }
}
