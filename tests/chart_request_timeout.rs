//! The chart's `taskDb.requestTimeoutSeconds` is bounded by the dial this
//! binary pins, and this is where that bound stops being a comment (ADR-0925
//! Q-C1, ledger 1490).
//!
//! `chart/values.schema.json` states a `minimum` and a `maximum`; `yadgar_dial`
//! states the same two numbers as `min_request_timeout()` and
//! `max_request_timeout()`. Nothing held them together: bump the pin to a dial
//! that widens or narrows the range, and the chart would admit a value the
//! binary refuses at boot, or refuse one the binary accepts. This test reds on
//! that bump, beside the two numbers it compares.
//!
//! Every number is also pinned by a LITERAL (ADR-0599), so a change to the
//! constant and the schema together is still a deliberate edit here.

use std::path::PathBuf;

use serde_json::Value;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()))
}

fn schema_property() -> Value {
    let schema: Value = serde_json::from_str(&read("chart/values.schema.json"))
        .expect("chart/values.schema.json must be valid JSON");
    let block = &schema["properties"]["taskDb"];
    assert!(block.is_object(), "the schema has no `taskDb` block");
    assert!(
        block["required"]
            .as_array()
            .is_some_and(|r| r.iter().any(|k| k == "requestTimeoutSeconds")),
        "`taskDb.requestTimeoutSeconds` must be `required`: the binary has no default (ADR-0569)"
    );
    block["properties"]["requestTimeoutSeconds"].clone()
}

#[test]
fn the_schema_bounds_are_the_dial_bounds() {
    let property = schema_property();
    assert_eq!(property["type"], "integer");
    let minimum = property["minimum"].as_u64().expect("`minimum` must be set");
    let maximum = property["maximum"].as_u64().expect("`maximum` must be set");

    assert_eq!(
        minimum,
        yadgar_dial::min_request_timeout().as_secs(),
        "the chart's minimum is not the floor the pinned dial refuses below"
    );
    assert_eq!(
        maximum,
        yadgar_dial::max_request_timeout().as_secs(),
        "the chart's maximum is not the ceiling the pinned dial refuses above"
    );
    assert_eq!(
        minimum, 14,
        "the floor moved; see the dial's keepalive derivation"
    );
    assert_eq!(
        maximum, 59,
        "the ceiling moved; it sits below the 60s ingress idle timeout"
    );
}

/// The default is stated in `chart/values.yaml`, inside the `taskDb:` block.
fn values_default() -> u64 {
    let values = read("chart/values.yaml");
    let mut in_block = false;
    let mut found = Vec::new();
    for line in values.lines() {
        if !line.starts_with(' ') && !line.starts_with('#') && !line.is_empty() {
            in_block = line.starts_with("taskDb:");
        }
        if in_block {
            if let Some(rest) = line.strip_prefix("  requestTimeoutSeconds:") {
                found.push(
                    rest.split('#')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                );
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected one `taskDb.requestTimeoutSeconds`, got {found:?}"
    );
    found[0]
        .parse()
        .unwrap_or_else(|why| panic!("`{}` is not an integer: {why}", found[0]))
}

/// ADR-1006: the timeout chain shrinks inward, so this hop's default is 14 —
/// below the gateway's 16 for its hop to task, above task-db's 12 s pool
/// acquire, and exactly dial's floor. Neither neighbour's value is visible from
/// this repository; the parent chart (`yadgarhq/yadgar`) is where a cross-chart
/// check can compare them (ledger 1524).
#[test]
fn the_chart_default_is_14_and_inside_the_bounds() {
    let default = values_default();
    assert_eq!(default, 14, "the ruled default (ADR-1006) moved");
    assert!(
        (yadgar_dial::min_request_timeout().as_secs()
            ..=yadgar_dial::max_request_timeout().as_secs())
            .contains(&default),
        "the chart default is outside the range the binary accepts"
    );
    assert!(
        default > 12,
        "the request timeout must stay above the -db's pool acquire timeout (12s, ADR-1006), or \
         a request waiting on a pool slot is cut before the pool gives up"
    );
    assert!(
        default < 16,
        "the request timeout must stay below the gateway's 16s for its hop to task (ADR-1006): \
         each hop times out strictly before its caller"
    );
}

#[test]
fn the_deployment_renders_the_variable_from_the_chart_key() {
    let deployment = read("chart/templates/deployment.yaml");
    let at = deployment
        .find("- name: TASK_DB_REQUEST_TIMEOUT_SECONDS")
        .expect("deployment.yaml must render TASK_DB_REQUEST_TIMEOUT_SECONDS");
    let next: String = deployment[at..]
        .lines()
        .take(2)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        next.contains(".Values.taskDb.requestTimeoutSeconds"),
        "TASK_DB_REQUEST_TIMEOUT_SECONDS is not rendered from `taskDb.requestTimeoutSeconds`: {next}"
    );
}
