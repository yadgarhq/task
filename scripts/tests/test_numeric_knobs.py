"""NUMERIC KNOBS RENDER AS WHOLE NUMBERS, OR THE RENDER REFUSES NAMING THE KEY (yaadgaar 482, 485).

A values FILE decodes every number as float64, and `quote` prints a float64 with `%v`:
1000000 becomes "1e+06". The binary parses neither. `int64` repairs the rendering but is
silent on a value that does not fit (1e20 becomes -9223372036854775808) and reads a
string base 0 ("0123" is 83), so every numeric knob is checked BEFORE the cast
(`templates/render-checks.yaml`): a string is at most 18 digits with no leading zero, a
number is whole and below 1e18, and the refusal names the key.

`replicaCount` 0 stays legal while autoscaling is off (ruled 2026-11-03), and
`test_zero_replicas_still_render` pins it. `autoscaling.minReplicas` below 2 is refused
while autoscaling is on (D55, yaadgaar 482), pinned at the end of this file.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
KEDA = ("--api-versions", "keda.sh/v1alpha1")
INT32_MAX = 2147483647


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED. PyYAML leaves `1e3` and `08` bare, and helm's
    parser then reads them as the numbers 1000 and 8, so a case meant to hand the chart
    a string would hand it a number."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def overlay(path: str, value, *, autoscaling: bool = False) -> dict:
    body: dict = {"autoscaling": {"enabled": True}} if autoscaling else {}
    node = body
    *parents, leaf = path.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value
    return body


def render(body: dict, tmp_path: Path, *extra: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), "-f", str(values), *extra)


def rendered(body: dict, tmp_path: Path, *extra: str) -> str:
    result = render(body, tmp_path, *extra)
    assert result.returncode == 0, result.stderr
    return result.stdout


def refused_naming(body: dict, key: str, tmp_path: Path, *extra: str) -> str:
    result = render(body, tmp_path, *extra)
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert key in combined, combined
    return combined


def objects(stdout: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(stdout) if isinstance(d, dict) and d.get("apiVersion")]


def deployment(stdout: str) -> dict:
    (found,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    return found


def env(stdout: str) -> dict[str, str]:
    (container,) = deployment(stdout)["spec"]["template"]["spec"]["containers"]
    return {e["name"]: e["value"] for e in container["env"] if "value" in e}


PORT_KNOBS = [("taskDb.port", "TASK_DB_PORT")]


@pytest.mark.parametrize("key,var", PORT_KNOBS)
def test_a_port_renders_both_ends_and_refuses_one_past_each(key, var, tmp_path):
    for value in (1, 65535, 50052.0, "443"):
        assert env(rendered(overlay(key, value), tmp_path))[var] == str(int(value))
    for value in (0, 65536, "0", "65536", 1000000, -1, 1.5, "abc"):
        refused_naming(overlay(key, value), key, tmp_path)


def test_a_values_file_replica_count_renders_as_an_integer(tmp_path):
    stdout = rendered(overlay("replicaCount", 1000000), tmp_path)
    assert "replicas: 1000000\n" in stdout
    assert "1e+06" not in stdout


def test_the_replica_count_ceiling_is_the_int32_field_and_both_ends_are_exact(tmp_path):
    assert f"replicas: {INT32_MAX}\n" in rendered(overlay("replicaCount", INT32_MAX), tmp_path)
    refused_naming(overlay("replicaCount", INT32_MAX + 1), "replicaCount", tmp_path)
    refused_naming(overlay("replicaCount", str(INT32_MAX + 1)), "replicaCount", tmp_path)


@pytest.mark.parametrize("value", [1.5, -1, "abc", "", "0123", 1e20, True, [], "9" * 19, "1" + "0" * 18], ids=repr)
def test_a_replica_count_that_is_not_whole_refuses_naming_the_key(value, tmp_path):
    refused_naming(overlay("replicaCount", value), "replicaCount", tmp_path)


def test_zero_replicas_still_render(tmp_path):
    """`replicaCount: 0` is legal (scale to zero, ruled 2026-11-03, yaadgaar 482). The KEDA
    floor is a separate rule, tested at the end of this file."""
    stdout = rendered(overlay("replicaCount", 0), tmp_path)
    assert "replicas: 0\n" in stdout


def test_the_autoscaling_counts_render_as_integers_and_bound_both_ends(tmp_path):
    body = overlay("autoscaling.minReplicas", 1000000, autoscaling=True)
    body["autoscaling"]["maxReplicas"] = 2000000
    stdout = rendered(body, tmp_path, *KEDA)
    assert "minReplicaCount: 1000000\n" in stdout
    assert "maxReplicaCount: 2000000\n" in stdout
    assert "1e+06" not in stdout and "2e+06" not in stdout
    for key in ("minReplicas", "maxReplicas"):
        assert rendered(overlay(f"autoscaling.{key}", INT32_MAX, autoscaling=True), tmp_path, *KEDA)
        over = overlay(f"autoscaling.{key}", INT32_MAX + 1, autoscaling=True)
        refused_naming(over, f"autoscaling.{key}", tmp_path, *KEDA)
        for value in (1.5, "abc", -1, ""):
            bad = overlay(f"autoscaling.{key}", value, autoscaling=True)
            refused_naming(bad, f"autoscaling.{key}", tmp_path, *KEDA)


def test_the_autoscaling_counts_are_not_read_while_autoscaling_is_off(tmp_path):
    assert rendered(overlay("autoscaling.maxReplicas", 1.5), tmp_path)


def test_a_zero_timing_knob_still_means_not_rendered(tmp_path):
    spec = deployment(rendered(overlay("terminationGracePeriodSeconds", 0), tmp_path))["spec"]["template"]["spec"]
    assert "terminationGracePeriodSeconds" not in spec


DEPLOYMENT = CHART / "templates" / "deployment.yaml"
# Per key: the anchored pattern that finds every line of the template that renders the
# key, and the one exact line that is allowed. A comment that quotes the cast cannot
# stand in for it, because the render line is found first and must fullmatch.
CAST_SITES = [
    (r"^[ \t]*terminationGracePeriodSeconds: \{\{.*$", r"^[ \t]*terminationGracePeriodSeconds: \{\{ \. \| int64 \}\}$"),
    (r"^[ \t]*seconds: \{\{.*$", r"^[ \t]*seconds: \{\{ \. \| int64 \}\}$"),
    (r"^[ \t]*- maxSkew: \{\{.*$", r"^[ \t]*- maxSkew: \{\{ \.Values\.topologySpread\.maxSkew \| int64 \}\}$"),
]


@pytest.mark.parametrize("render,cast", CAST_SITES, ids=["grace", "preStop", "maxSkew"])
def test_the_grace_period_pre_stop_sleep_and_skew_render_through_int64(render, cast):
    """Cast, like every other numeric knob (yaadgaar 550). The chart-baseline gate reads
    `| int64` since actions v1.64.0, so the cast no longer costs the gate its view of the
    value. `| int` is not the same cast and does not count. Every value the check below
    admits renders the same bytes with or without the cast, so this pin is the only test
    that holds the cast in place. It finds every line that renders the key, requires
    exactly one, and requires that line to be the cast form with nothing after it: a
    substring count would pass a dropped cast whose text lives on in a trailing comment."""
    lines = re.findall(render, DEPLOYMENT.read_text(), re.M)
    assert len(lines) == 1, f"{render!r} matches {len(lines)} render lines in deployment.yaml, want exactly 1: {lines}"
    assert re.fullmatch(cast, lines[0]), f"the render line is not the int64 cast form: {lines[0]!r}"


def test_the_grace_period_and_pre_stop_sleep_are_bounded_where_a_float_prints_plainly(tmp_path):
    """Cast through `int64` and still bounded at 999999, by choice (yaadgaar 550): the
    gate no longer forces the bound, and lifting it is a separate decision. The
    whole-number check runs BEFORE the cast, because `int64` turns 1.5 into 1."""
    spec = deployment(rendered(overlay("terminationGracePeriodSeconds", 999999), tmp_path))["spec"]["template"]["spec"]
    assert spec["terminationGracePeriodSeconds"] == 999999
    stdout = rendered(overlay("preStopSleepSeconds", 999999), tmp_path)
    assert "seconds: 999999\n" in stdout
    for key in ("terminationGracePeriodSeconds", "preStopSleepSeconds"):
        for value in (1000000, 1.5, "abc", -1, "0123", 1e20, ""):
            refused_naming(overlay(key, value), key, tmp_path)


def test_an_eighteen_digit_replica_count_string_is_the_string_ceiling(tmp_path):
    """18 digits fit int64 and are refused only by the int32 bound; 19 overflow the cast
    to 0 and are refused by the whole-number check. Both name the key."""
    refused_naming(overlay("replicaCount", "9" * 18), "replicaCount", tmp_path)
    refused_naming(overlay("replicaCount", "9" * 19), "replicaCount", tmp_path)
    assert "replicas: 2147483647\n" in rendered(overlay("replicaCount", str(INT32_MAX)), tmp_path)


def test_the_topology_skew_is_bounded_where_a_float_prints_plainly(tmp_path):
    """Cast through `int64` and still bounded, by choice (yaadgaar 550). The API needs
    maxSkew > 0, so 0 is refused; 999999 is the largest value helm prints without an
    exponent, and that ceiling is kept."""
    def skew(value):
        body = overlay("topologySpread.maxSkew", value)
        body["topologySpread"]["enabled"] = True
        return body

    for value in (1, 999999):
        spec = deployment(rendered(skew(value), tmp_path))["spec"]["template"]["spec"]
        assert spec["topologySpreadConstraints"][0]["maxSkew"] == value
    for value in (0, "0", 1000000, 1.5, "abc", -1, "", "0123", 1e20):
        refused_naming(skew(value), "topologySpread.maxSkew", tmp_path)


def test_the_topology_skew_is_not_read_while_the_spread_is_off(tmp_path):
    body = overlay("topologySpread.maxSkew", 1.5)
    body["topologySpread"]["enabled"] = False
    assert rendered(body, tmp_path)


# --- 482 item 2: autoscaling.minReplicas >= 2 while autoscaling is on (D55) --------
# RULED 2026-11-03: D55 makes two pods a correctness property, so KEDA `minReplicaCount`
# below 2 is refused at render. `replicaCount: 0` stays legal while autoscaling is off.


@pytest.mark.parametrize("value", [0, 1, "0", "1"], ids=repr)
def test_autoscaling_on_with_min_replicas_below_two_is_refused_by_name(tmp_path, value):
    body = overlay("autoscaling.minReplicas", value, autoscaling=True)
    combined = refused_naming(body, "autoscaling.minReplicas", tmp_path, *KEDA)
    assert "at least 2" in combined, combined


@pytest.mark.parametrize("value", [2, 3, "2"], ids=repr)
def test_autoscaling_on_with_min_replicas_two_or_more_renders(tmp_path, value):
    body = overlay("autoscaling.minReplicas", value, autoscaling=True)
    assert f"minReplicaCount: {int(value)}\n" in rendered(body, tmp_path, *KEDA)


def test_the_min_replicas_floor_is_not_read_while_autoscaling_is_off(tmp_path):
    body = overlay("autoscaling.minReplicas", 0)
    body["replicaCount"] = 0
    assert "replicas: 0\n" in rendered(body, tmp_path)


def test_a_string_autoscaling_toggle_is_refused_before_the_floor_is_read(tmp_path):
    """`enabled: "false"` reads as off to a human and truthy to Go templates. The bool-shape
    check must refuse it first, so `minReplicas: 0` never slips past the floor behind it."""
    body = overlay("autoscaling.minReplicas", 0)
    body["autoscaling"]["enabled"] = "false"
    combined = refused_naming(body, "autoscaling.enabled", tmp_path, *KEDA)
    assert "must be true or false" in combined and "at least 2" not in combined, combined
