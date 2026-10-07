"""What `chart/values.schema.json` closes, and what it leaves for render-checks.yaml.

ADR-0847 rules closed schemas; render checks own types. ADR-0850 rules closure is
PER CHART: this file closes only the keys `task` itself owns, and declares
`global` open — the key every subchart the parent's coalesced tree receives,
whether or not THIS chart's own templates read `.Values.global` (measured: an
undeclared `global` refuses the parent's own default render).

UNTYPED CLOSURE AT EVERY BLOCK, TYPED NOWHERE. A mapping in `values.yaml` becomes
`{"properties": {...}, "additionalProperties": false}` with NO `type`, so a
scalar or `null` written where a block belongs passes THIS schema and reaches the
render check instead: `autoscaling: "x"` is `test_render_checks.py`'s territory
(measured on iam#90 and the ledger-sweep draft: the `must be a map` sentence, no
schema line). A LEAF is `{}` — no type, no enum, no default, no required. `task`
ships no retained typed leaf today (unlike gateway's `toolsPoll.intervalSeconds`
or the twins' `database.migrationLockTimeoutSeconds`), so nothing here is
exempted from that rule, and `required` on any new key is explicitly OUT OF
SCOPE for this PR — `tls.enabled` and `taskDb.tls.enabled` get `required` in
C-SVb (ADR-0845, ADR-0857/K-8), never in D-S.

THE TWO EXTRAS (keys `values.yaml` omits by design, found by grepping
`chart/templates` for `.Values` paths `values.yaml` does not declare):
`image.digest` (`templates/deployment.yaml` builds the published image
reference from it; ci-release rewrites it at package time, D65) and
`networkPolicy.scrapeFrom.namespace` (`values.yaml` ships `scrapeFrom: {}`;
`templates/networkpolicy.yaml` reads the nested key directly). Both are
declared as leaves inside otherwise-closed blocks.

THE OPEN MAPS, AND WHY: `global` (above); `resources`
(`templates/deployment.yaml` does `toYaml .Values.resources` unexamined);
`rollingUpdate` (`{{- with .Values.rollingUpdate }}` writes back whatever map it
is handed, so `rollingUpdate: {}` returning the field to Kubernetes' own default
has to stay legal). `networkPolicy.clients` is a LIST, not a block, and lists
are `{}` too: its items are unindexed strings from `range $clients`, not
gateway's typed peer objects — this chart's copy of `networkpolicy.yaml` is not
gateway's.

Tests assert the SCHEMA KEY and the JSON PATH FRAGMENT only, never helm's
wording: helm 3.18.4 prints `<path>: Additional property X is not allowed`;
helm 3.20.2 and 4.3.0 print `at '/<path>': additional properties 'X' not
allowed`.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
SCHEMA = CHART / "values.schema.json"
VALUES = CHART / "values.yaml"

# ── WHAT THE SHIPPED TREE SAYS, WRITTEN DOWN ─────────────────────────────────

# `global` is helm's own reserved key (ADR-0850): declared open, not a knob
# `values.yaml` ever states, so it is subtracted from the schema's leaf set
# before comparing it against what `values.yaml` and the extras supply.
RESERVED = ("global",)

# Keys `templates/*.yaml` reads that `values.yaml` omits by design (module
# docstring above). A LITERAL tuple: a set derived from the schema or the
# templates would agree with whatever either happens to say and prove nothing.
EXTRAS = ("image.digest", "networkPolicy.scrapeFrom.namespace")

# `values.yaml` paths where the schema stops descending and declares the whole
# subtree `{}` (an open map) rather than naming each key inside it.
OPEN_VALUES_PATHS = ("resources", "rollingUpdate")


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), *arguments)


def values_file(tmp_path: Path, name: str, body) -> str:
    path = tmp_path / f"{name}.yaml"
    path.write_text(body if isinstance(body, str) else yaml.safe_dump(body))
    return str(path)


def load_schema() -> dict:
    return json.loads(SCHEMA.read_text())


def load_values() -> dict:
    return yaml.safe_load(VALUES.read_text()) or {}


def schema_leaves(node: dict, prefix: str = "") -> Iterable[str]:
    """Every leaf path the schema declares, dotted. PURE."""
    for key, subschema in (node or {}).items():
        path = f"{prefix}.{key}" if prefix else str(key)
        nested = (subschema or {}).get("properties")
        if isinstance(nested, dict) and nested:
            yield from schema_leaves(nested, path)
        else:
            yield path


def schema_blocks(node: dict, prefix: str = "") -> Iterable[tuple[str, dict]]:
    """Every `(path, subschema)` the schema closes with its own `properties`. PURE."""
    for key, subschema in (node or {}).items():
        path = f"{prefix}.{key}" if prefix else str(key)
        nested = (subschema or {}).get("properties")
        if isinstance(nested, dict) and nested:
            yield path, subschema
            yield from schema_blocks(nested, path)


def values_leaves(node: dict, open_paths: Iterable[str], prefix: str = "") -> Iterable[str]:
    """Every `values.yaml` leaf path, stopping descent at an open-map path. PURE."""
    for key, value in (node or {}).items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if path in open_paths:
            yield path
        elif isinstance(value, dict) and value:
            yield from values_leaves(value, open_paths, path)
        else:
            yield path


def declared_key_set(schema: dict) -> set[str]:
    return set(schema_leaves(schema["properties"])) - set(RESERVED)


def supplied_key_set(values: dict) -> set[str]:
    """`values.yaml`'s own leaves plus the extras. PURE.

    An EMPTY mapping in `values.yaml` (`scrapeFrom: {}`) is itself a leaf by
    `values_leaves`' rule — until an extra names a key inside it, which turns
    that mapping into a closed block of one and retires the mapping's own path
    as a leaf. `networkPolicy.scrapeFrom` is that case: the extra
    `networkPolicy.scrapeFrom.namespace` supersedes it.
    """
    extra_parents = {extra.rsplit(".", 1)[0] for extra in EXTRAS if "." in extra}
    leaves = set(values_leaves(values, OPEN_VALUES_PATHS)) - extra_parents
    return leaves | set(EXTRAS)


def root_closed(schema: dict) -> bool:
    return schema.get("additionalProperties") is False


def open_block_violations(schema: dict) -> list[str]:
    """Paths whose `properties` node is not closed. Empty means fully closed. PURE."""
    return [
        path
        for path, subschema in schema_blocks(schema["properties"])
        if subschema.get("additionalProperties") is not False
    ]


def leaf_type_violations(node: dict) -> list[str]:
    """Paths carrying `type`, `enum`, `default` or `required` — none belong here. PURE."""
    violations = []
    for key in ("type", "enum", "default", "required"):
        if key in node:
            violations.append(key)
    for subschema in (node.get("properties") or {}).values():
        violations.extend(leaf_type_violations(subschema))
    return violations


# ── THE SCHEMA ITSELF, ON THE SHIPPED TREE ───────────────────────────────────


def test_the_schema_closes_its_root():
    assert root_closed(load_schema())


def test_the_schema_closes_every_block():
    assert open_block_violations(load_schema()) == []


def test_the_schema_declares_exactly_the_keys_values_yaml_and_the_extras_supply():
    assert declared_key_set(load_schema()) == supplied_key_set(load_values())


def test_the_schema_declares_global_as_a_bare_open_map():
    assert load_schema()["properties"]["global"] == {}


def test_the_open_maps_stay_bare():
    schema = load_schema()
    assert schema["properties"]["resources"] == {}
    assert schema["properties"]["rollingUpdate"] == {}
    assert schema["properties"]["networkPolicy"]["properties"]["clients"] == {}


def test_the_extras_are_leaves_inside_closed_blocks():
    schema = load_schema()
    image = schema["properties"]["image"]
    assert image["properties"]["digest"] == {}
    assert image["additionalProperties"] is False
    scrape_from = schema["properties"]["networkPolicy"]["properties"]["scrapeFrom"]
    assert scrape_from["properties"]["namespace"] == {}
    assert scrape_from["additionalProperties"] is False


def test_no_type_enum_default_or_required_anywhere():
    schema = load_schema()
    assert "type" not in schema
    assert "required" not in schema
    assert leaf_type_violations(schema) == []


def test_the_retained_leaves_are_untyped_task_ships_none():
    """`task` carries no typed leaf (unlike gateway's `toolsPoll` or the twins'
    `migrationLockTimeoutSeconds`), so EVERY leaf here is `{}` and this is a
    census, not a spot check.
    """
    schema = load_schema()
    for path in schema_leaves(schema["properties"]):
        if path in RESERVED:
            continue
        leaf = schema
        for step in path.split("."):
            leaf = leaf["properties"][step]
        assert leaf == {}, path


# ── MUTATIONS, EACH MUST REDDEN ───────────────────────────────────────────────


def test_mutation_deleting_root_additionalProperties_reddens_root_closure():
    mutant = copy.deepcopy(load_schema())
    del mutant["additionalProperties"]
    assert not root_closed(mutant)


def test_mutation_opening_a_closed_block_reddens_block_closure():
    mutant = copy.deepcopy(load_schema())
    del mutant["properties"]["autoscaling"]["additionalProperties"]
    assert open_block_violations(mutant) == ["autoscaling"]


def test_mutation_deleting_global_reddens_the_global_gate():
    mutant = copy.deepcopy(load_schema())
    del mutant["properties"]["global"]
    assert mutant["properties"].get("global") != {}


def test_mutation_deleting_an_extra_reddens_the_key_set_gate():
    mutant = copy.deepcopy(load_schema())
    del mutant["properties"]["image"]["properties"]["digest"]
    assert declared_key_set(mutant) != supplied_key_set(load_values())


def test_mutation_closing_an_open_map_reddens_the_key_set_gate():
    mutant = copy.deepcopy(load_schema())
    mutant["properties"]["resources"] = {
        "properties": {"requests": {}, "limits": {}},
        "additionalProperties": False,
    }
    assert declared_key_set(mutant) != supplied_key_set(load_values())


# ── THE RED-CASE TABLE (rendered, both helms via the acceptance sweep) ───────


def test_root_typo_is_refused_by_name(tmp_path):
    """TODAY exits 0 — the schema is what makes this a refusal at all."""
    result = render("-f", values_file(tmp_path, "r1", {"autoscalng": {"enabled": True}}))
    assert result.returncode != 0
    assert "autoscalng" in result.stderr


def test_one_level_down_typo_is_refused_by_name(tmp_path):
    result = render("-f", values_file(tmp_path, "r2", {"autoscaling": {"enabeld": True}}))
    assert result.returncode != 0
    assert "enabeld" in result.stderr


def test_two_levels_down_typo_is_refused_by_name(tmp_path):
    body = {"networkPolicy": {"scrapeFrom": {"namespac": "x"}}}
    result = render("-f", values_file(tmp_path, "r3", body))
    assert result.returncode != 0
    assert "namespac" in result.stderr


def test_wrong_type_toggle_is_a_render_check_not_a_schema_line(tmp_path):
    """The schema is UNTYPED on leaves (ADR-0847): `autoscaling.enabled: "false"`
    passes the schema and reaches `render-checks.yaml`'s own `kindIs "bool"`
    guard (D-M, ledger 1135), landed on `main` before this PR.
    """
    body = {"autoscaling": {"enabled": "false"}}
    result = render(
        "--api-versions", "keda.sh/v1alpha1", "-f", values_file(tmp_path, "t1", body)
    )
    assert result.returncode != 0
    assert "must be true or false" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_block_scalar_is_a_render_check_not_a_schema_line(tmp_path):
    result = render("-f", values_file(tmp_path, "t2", {"autoscaling": "x"}))
    assert result.returncode != 0
    assert "must be a map" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_deleted_autoscaling_enabled_is_a_render_check_not_a_schema_line(tmp_path):
    result = render("-f", values_file(tmp_path, "t3", "autoscaling:\n  enabled:\n"))
    assert result.returncode != 0
    assert "is absent" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_open_map_rows_render_clean(tmp_path):
    for name, body in (
        ("o1", {"resources": {"foo": {"bar": 1}}}),
        ("o2", {"global": {"whatever": 1}}),
        ("o3", {"rollingUpdate": {"partition": 1}}),
    ):
        result = render("-f", values_file(tmp_path, name, body))
        assert result.returncode == 0, (name, result.stderr)


def test_extra_image_digest_renders_clean(tmp_path):
    body = {"image": {"digest": "sha256:" + "a" * 64}}
    result = render("-f", values_file(tmp_path, "o4", body))
    assert result.returncode == 0, result.stderr


def test_untyped_leaf_accepts_a_stringly_set(tmp_path):
    """Type is not the schema's job (ADR-0847): `--set-string` on a leaf renders clean."""
    result = render("--set-string", "replicaCount=2")
    assert result.returncode == 0, result.stderr


def test_lint_strict_refuses_the_root_typo_too():
    """BOTH gates: `helm lint --strict` is the `helm lint and render` hook (`ci /
    passed`); `helm template` is what Argo runs. A schema enforced by only one
    would be a gate an adopter never meets.
    """
    result = helm(
        "lint", "--strict", str(CHART), "--set", "autoscalng.enabled=true"
    )
    assert result.returncode != 0
    assert "autoscalng" in (result.stdout + result.stderr)


def test_the_default_render_is_unchanged(tmp_path):
    """RENDER-NEUTRALITY (ADR-0645): the schema refuses nothing the chart's own
    default values ask for.
    """
    result = render()
    assert result.returncode == 0, result.stderr
    objects = [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]
    assert len(objects) == 4
    assert sorted(document["kind"] for document in objects) == [
        "Deployment",
        "PodDisruptionBudget",
        "Service",
        "ServiceAccount",
    ]


def test_the_suite_reads_the_chart_this_repository_ships():
    assert CHART == REPO / "chart", CHART
    assert SCHEMA.exists(), SCHEMA
    assert yaml.safe_load((CHART / "Chart.yaml").read_text())["name"] == "task"
