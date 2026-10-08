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

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
SCHEMA = CHART / "values.schema.json"
VALUES = CHART / "values.yaml"
CI_VALUES = CHART / "ci" / "values.yaml"

# ── WHAT THE SHIPPED TREE SAYS, WRITTEN DOWN ─────────────────────────────────

# `global` is helm's own reserved key (ADR-0850): declared open, not a knob
# `values.yaml` ever states, so it is subtracted from the schema's leaf set
# before comparing it against what `values.yaml` and the extras supply.
RESERVED = ("global",)

# Keys `templates/*.yaml` reads that `values.yaml` omits by design (module
# docstring above). A LITERAL tuple: a set derived from the schema or the
# templates would agree with whatever either happens to say and prove nothing.
#
# `tls.clientAuth`, `tls.clientCaSecret`, `tls.clientCaSecretKey`: the B-U5E
# expand (ADR-0854, folded into C-SVb). Declared so an adopter's override is
# validated by the closure, but `values.yaml` ships none of the three — the
# binary does not read LISTEN_TLS_CLIENT_AUTH at all until B-U5 adopts it.
EXTRAS = (
    "image.digest",
    "networkPolicy.scrapeFrom.namespace",
    "tls.clientAuth",
    "tls.clientCaSecret",
    "tls.clientCaSecretKey",
)

# `values.yaml` paths where the schema stops descending and declares the whole
# subtree `{}` (an open map) rather than naming each key inside it.
OPEN_VALUES_PATHS = ("resources", "rollingUpdate")

# THE EXACT SET OF SCHEMA LEAVES THIS CHART REQUIRES AND SHIPS NO DEFAULT FOR
# (ADR-0845, C-SVb). Neither is an EXTRA: an extra is a key `values.yaml`
# omits by design with NO constraint attached; these two are omitted by
# design AND an adopter MUST choose one of exactly two values, which is what
# `type: boolean` plus the parent block's `required: [enabled]` state in the
# schema. Excluded here from the key-set census (below), from
# `test_no_type_enum_default_or_required_anywhere`, and from
# `test_the_retained_leaves_are_untyped_task_ships_none` — all three would
# otherwise read this card's own schema change as the defect they exist to
# catch. `test_every_required_no_default_key_has_no_default_in_values_yaml`
# and `test_every_required_no_default_key_is_required_in_the_schema` are this
# set's own two-sided proof instead: absent from `values.yaml`, present and
# `required` in the schema.
REQUIRED_NO_DEFAULT = ("tls.enabled", "taskDb.tls.enabled")


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
    # `-f CI_VALUES` FIRST, ALWAYS, WHEN THE FILE EXISTS (ADR-0845, C-SVb):
    # `tls.enabled` and `taskDb.tls.enabled` carry no default any more, and
    # this chart's own `ci/values.yaml` is the one place that states the
    # baseline every other render in this file renders against — the same
    # contract `chart_values_override.py` documents for the shared
    # `helm-lint` hook. First, not last, so a case-specific `--values`/`--set`
    # in `*arguments` still wins on any key the two happen to share.
    override = ("-f", str(CI_VALUES)) if CI_VALUES.is_file() else ()
    return helm("template", "x", str(CHART), *override, *arguments)


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


def leaf_type_violations(node: dict, prefix: str = "") -> list[str]:
    """Paths carrying `type`, `enum`, `default` or `required` — none belong
    here, EXCEPT where ADR-0845 put them on purpose (REQUIRED_NO_DEFAULT:
    `tls.enabled` and `taskDb.tls.enabled`). PURE.
    """
    violations = []
    for key in ("type", "enum", "default"):
        if key in node and prefix not in REQUIRED_NO_DEFAULT:
            violations.append(key)
    if "required" in node:
        required_paths = {f"{prefix}.{name}" if prefix else name for name in node["required"]}
        if not required_paths <= set(REQUIRED_NO_DEFAULT):
            violations.append("required")
    for key, subschema in (node.get("properties") or {}).items():
        subprefix = f"{prefix}.{key}" if prefix else key
        violations.extend(leaf_type_violations(subschema, subprefix))
    return violations


# ── THE SCHEMA ITSELF, ON THE SHIPPED TREE ───────────────────────────────────


def test_the_schema_closes_its_root():
    assert root_closed(load_schema())


def test_the_schema_closes_every_block():
    assert open_block_violations(load_schema()) == []


def test_the_schema_declares_exactly_the_keys_values_yaml_and_the_extras_supply():
    # REQUIRED_NO_DEFAULT keys are declared in the schema but deliberately
    # absent from `values.yaml` (ADR-0845) — see that set's own comment.
    assert declared_key_set(load_schema()) - set(REQUIRED_NO_DEFAULT) == supplied_key_set(
        load_values()
    )


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
    """`task` carries no typed leaf OTHER than the two REQUIRED_NO_DEFAULT
    keys ADR-0845/C-SVb typed on purpose (unlike gateway's `toolsPoll` or the
    twins' `migrationLockTimeoutSeconds`), so every OTHER leaf here is `{}`
    and this is a census, not a spot check.
    """
    schema = load_schema()
    for path in schema_leaves(schema["properties"]):
        if path in RESERVED or path in REQUIRED_NO_DEFAULT:
            continue
        leaf = schema
        for step in path.split("."):
            leaf = leaf["properties"][step]
        assert leaf == {}, path


def test_the_required_no_default_leaves_are_typed_boolean():
    schema = load_schema()
    for path in REQUIRED_NO_DEFAULT:
        leaf = schema
        for step in path.split("."):
            leaf = leaf["properties"][step]
        assert leaf == {"type": "boolean"}, path


def test_every_required_no_default_key_has_no_default_in_values_yaml():
    """The other half of what REQUIRED_NO_DEFAULT claims: `values.yaml`
    really does not set it. A key that crept back into `values.yaml` would
    still pass the key-set test above (it is subtracted there, not merely
    tolerated), so this is the test that would catch it.
    """
    values = load_values()
    for path in REQUIRED_NO_DEFAULT:
        node = values
        present = True
        for step in path.split("."):
            if not isinstance(node, dict) or step not in node:
                present = False
                break
            node = node[step]
        assert not present, (
            f"{path} is in REQUIRED_NO_DEFAULT but values.yaml sets it — "
            "ADR-0845 asks for no default, not merely an unenforced one"
        )


def test_every_required_no_default_key_is_required_in_the_schema():
    """The schema half: a key with no default must be `required` by its
    parent block, or an adopter who omits it gets `null`/zero rather than a
    refusal naming the key.
    """
    schema = load_schema()
    for path in REQUIRED_NO_DEFAULT:
        *parents, leaf_key = path.split(".")
        cursor = schema
        for step in parents:
            cursor = cursor["properties"][step]
        assert leaf_key in cursor.get("required", []), (
            f"{path} is in REQUIRED_NO_DEFAULT but its parent block does not "
            "list it under `required`"
        )


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


# ── RED CASES: `tls.enabled` AND `taskDb.tls.enabled` CARRY NO DEFAULT (ADR-0845) ──
#
# Schema refusals below assert the stable WRAPPER sentence plus the key and
# its path segment only, never helm's per-leaf wording — measured identical
# on 4.3.0 and 3.20.2 ("at '/tls': missing property 'enabled'") and 3.18.4
# ("tls: enabled is required"); only the wrapper below is common to both.
# Render-check refusals assert the exact designed sentence, because that
# text is this chart's own and does not vary by helm version.
SCHEMA_REFUSAL_WRAPPER = "values don't meet the specifications of the schema(s)"


@pytest.mark.parametrize(
    ("key", "parent", "var"),
    [("tls", "tls", "LISTEN_TLS_ENABLED"), ("taskDb", "taskDb.tls", "TASK_DB_TLS_ENABLED")],
)
def test_enabled_wrong_type_is_refused_by_the_schema_naming_key_and_path(
    tmp_path, key, parent, var
):
    body = {key: {"enabled": "true"}} if key == "tls" else {"taskDb": {"tls": {"enabled": "true"}}}
    result = render("-f", values_file(tmp_path, f"wt-{key}", body))
    assert result.returncode != 0, result.stdout
    assert SCHEMA_REFUSAL_WRAPPER in result.stderr, result.stderr
    assert "enabled" in result.stderr
    assert parent.split(".")[-1] in result.stderr or parent in result.stderr


@pytest.mark.parametrize("path", ["tls", "taskDb"])
def test_enabled_null_is_refused_by_the_schema_naming_the_key(tmp_path, path):
    """`enabled: null` is NOT the same shape as the whole block set to null,
    below: `values.yaml` carries no default for `enabled` any more, so
    helm's null-key-deletion (which only drops a key the chart's OWN
    defaults also set) does not apply to it — the null survives into the
    merged values as a value, and the schema refuses it as the wrong type
    rather than as a missing key.
    """
    body = {"tls": {"enabled": None}} if path == "tls" else {"taskDb": {"tls": {"enabled": None}}}
    result = render("-f", values_file(tmp_path, f"null-{path}", body))
    assert result.returncode != 0, result.stdout
    assert SCHEMA_REFUSAL_WRAPPER in result.stderr, result.stderr
    assert "enabled" in result.stderr
    assert path in result.stderr


def test_tls_block_null_is_refused_naming_tls_by_the_render_check(tmp_path):
    """THE OTHER NULL SHAPE: `tls:` with no value deletes the WHOLE block
    this chart's `values.yaml` declares (it, unlike `enabled`, still carries
    defaults — `certSecret` etc.) — so this reaches `templates/render-
    checks.yaml`'s `tls`-absent arm, not the schema.
    """
    result = render("-f", values_file(tmp_path, "tls-null-block", "tls:\n"))
    assert result.returncode != 0, result.stdout
    assert "`tls` is absent from the values, so `tls.enabled` cannot be read" in result.stderr


def test_task_db_tls_block_null_is_refused_naming_task_db_tls_by_the_render_check(tmp_path):
    result = render(
        "-f", values_file(tmp_path, "taskdb-tls-null-block", "taskDb:\n  tls:\n")
    )
    assert result.returncode != 0, result.stdout
    assert (
        "`taskDb.tls.enabled` cannot be read" in result.stderr
        or "`taskDb.tls` is absent" in result.stderr
    )


def test_tls_not_a_map_is_refused_naming_tls_by_the_render_check(tmp_path):
    result = render("-f", values_file(tmp_path, "tls-not-map", {"tls": "x"}))
    assert result.returncode != 0, result.stdout
    assert "`tls` must be a map and is string" in result.stderr


# ── RED CASES: K-1 asserts the RENDERED VALUE, not just a successful render ──


def deployment_env(stdout: str) -> dict[str, str]:
    """The `env:` list of this chart's one Deployment, as a name -> value
    map. PURE. A substring check on raw YAML text cannot tell `"1"` apart
    from a comment that happens to mention it; this reads the actual
    rendered field.
    """
    for doc in yaml.safe_load_all(stdout):
        if isinstance(doc, dict) and doc.get("kind") == "Deployment":
            env = doc["spec"]["template"]["spec"]["containers"][0]["env"]
            return {item["name"]: item.get("value") for item in env}
    raise AssertionError("no Deployment in this render")


@pytest.mark.parametrize("enabled", [False, True])
def test_k1_unconditional_render_matches_the_switch(tmp_path, enabled):
    body = {"tls": {"enabled": enabled}, "taskDb": {"tls": {"enabled": enabled}}}
    result = render("-f", values_file(tmp_path, f"k1-{enabled}", body))
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    want = "1" if enabled else "0"
    assert env["LISTEN_TLS_ENABLED"] == want, env
    assert env["TASK_DB_TLS_ENABLED"] == want, env


# ── RED CASES: B-U5E's `tls.clientAuth` (ADR-0854, coordinator convention) ──


def test_client_auth_unquoted_off_is_refused_by_name(tmp_path):
    """YAML 1.1 reads a bare `off` as the boolean `false` (convention item 1):
    `clientAuth: off` parses to `false`, not the string `"off"`.
    """
    result = render(
        "-f", values_file(tmp_path, "ca-bare-off", "tls:\n  enabled: true\n  clientAuth: off\n")
    )
    assert result.returncode != 0, result.stdout
    assert "`tls.clientAuth` must be a quoted string" in result.stderr
    assert "write `clientAuth: \"off\"`" in result.stderr


def test_client_auth_optional_refuses_with_the_not_enforced_yet_sentence(tmp_path):
    body = {"tls": {"enabled": True, "clientAuth": "optional"}}
    result = render("-f", values_file(tmp_path, "ca-optional", body))
    assert result.returncode != 0, result.stdout
    assert "`tls.clientAuth: optional` is not enforced yet" in result.stderr


def test_client_auth_required_refuses_with_the_not_enforced_yet_sentence(tmp_path):
    body = {"tls": {"enabled": True, "clientAuth": "required"}}
    result = render("-f", values_file(tmp_path, "ca-required", body))
    assert result.returncode != 0, result.stdout
    assert "`tls.clientAuth: required` is not enforced yet" in result.stderr


def test_client_auth_bogus_value_is_refused(tmp_path):
    body = {"tls": {"enabled": True, "clientAuth": "bogus"}}
    result = render("-f", values_file(tmp_path, "ca-bogus", body))
    assert result.returncode != 0, result.stdout
    assert "must be `off`, `optional` or `required`" in result.stderr
    assert "bogus" in result.stderr


def test_client_auth_off_renders_the_env_var(tmp_path):
    body = {"tls": {"enabled": True, "clientAuth": "off"}}
    result = render("-f", values_file(tmp_path, "ca-off", body))
    assert result.returncode == 0, result.stderr
    assert deployment_env(result.stdout)["LISTEN_TLS_CLIENT_AUTH"] == "off"


def test_client_auth_absent_renders_no_client_auth_fields(tmp_path):
    """Convention item 6: an absent key must render NOTHING B-U5E adds — not
    the env vars, not the mount, not the volume. `tls.enabled: true` alone
    (what `chart/ci/values.yaml` already ships) is the fixture.
    """
    result = render()
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    assert "LISTEN_TLS_CLIENT_AUTH" not in env
    assert "LISTEN_TLS_CLIENT_CA_FILE" not in env
    assert "client-ca" not in result.stdout


def test_client_ca_secret_empty_renders_no_client_ca_fields(tmp_path):
    """Convention item 4: `clientCaSecret: ""` must not render
    `secretName: ""` — the gate is on TRUTHINESS, not `hasKey`.
    """
    body = {"tls": {"enabled": True, "clientAuth": "off", "clientCaSecret": ""}}
    result = render("-f", values_file(tmp_path, "ca-secret-empty", body))
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    assert "LISTEN_TLS_CLIENT_CA_FILE" not in env
    assert "client-ca" not in result.stdout
    # The OTHER B-U5E field is unaffected: `clientAuth: "off"` still renders.
    assert env["LISTEN_TLS_CLIENT_AUTH"] == "off"


def test_client_ca_secret_without_client_auth_renders_no_client_ca_fields(tmp_path):
    """The OTHER half of the same gate (review round 3): naming a CA bundle
    with no `clientAuth` stated is an incomplete expand. A real,
    non-empty `clientCaSecret` must still render nothing without
    `clientAuth` present — the authority this file would be checked against
    means nothing without the mode that checks it.
    """
    body = {"tls": {"enabled": True, "clientCaSecret": "x", "clientCaSecretKey": "ca.crt"}}
    result = render("-f", values_file(tmp_path, "ca-secret-no-auth", body))
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    assert "LISTEN_TLS_CLIENT_AUTH" not in env
    assert "LISTEN_TLS_CLIENT_CA_FILE" not in env
    assert "client-ca" not in result.stdout


def test_client_auth_fields_do_not_render_when_tls_is_off(tmp_path):
    """Convention item 3: client auth is nested under `tls.enabled`, not a
    sibling of it. A deployment that has not cut over `tls.enabled` sees no
    difference from stating `clientAuth` at all.
    """
    body = {
        "tls": {
            "enabled": False,
            "clientAuth": "off",
            "clientCaSecret": "task-client-ca",
            "clientCaSecretKey": "ca.crt",
        }
    }
    result = render("-f", values_file(tmp_path, "ca-tls-off", body))
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    assert "LISTEN_TLS_CLIENT_AUTH" not in env
    assert "LISTEN_TLS_CLIENT_CA_FILE" not in env
    assert "client-ca" not in result.stdout


def lint_bare() -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary
    return subprocess.run(
        ["helm", "lint", "--strict", str(CHART)], capture_output=True, text=True
    )


def test_a_bare_lint_refuses_the_missing_tls_enabled():
    """A bare `helm lint --strict .`, no `-f` at all — what an adopter who
    has not yet read `chart/ci/values.yaml` runs. `values.yaml` ships no
    default for either knob, so this is the SHAPE OF THE SCHEMA'S OWN
    CONTRIBUTION: `templates/render-checks.yaml`'s own `fail` logs as INFO
    under `lint` (helm grades a template `fail` as INFO, never ERROR), so
    this case is red ONLY because the schema's `required` makes it an ERROR.
    `test_dropping_tls_required_lets_a_bare_lint_pass` is this test's own
    mutation check.
    """
    result = lint_bare()
    combined = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert SCHEMA_REFUSAL_WRAPPER in combined, combined
    assert "enabled" in combined
    assert "tls" in combined


def test_dropping_tls_required_degrades_the_bare_lint_message(tmp_path):
    """MUTATION (card). A fresh copy of the WHOLE chart, because `-f` cannot
    replace `values.schema.json` itself — only editing the file on disk can.

    MEASURED (project-db#54, and reproduced here): with the render UNCONDITIONAL
    (`ternary` rather than `if`), dropping `required` does NOT let a bare
    `helm lint --strict` pass. `enabled` is truly absent once there is no
    chart default behind it, so the render-check's own `hasKey` guard still
    fires its `fail` — but `lint` grades a template `fail` as INFO, never
    ERROR, and keeps rendering anyway. What then throws the ACTUAL error is
    sprig's own `ternary`, handed a non-bool (`nil`) third argument:
    `invalid value; expected bool`. The exit code does not move; the MESSAGE
    an operator reads degrades from this chart's own named sentence to
    sprig's. That degradation, not red-vs-green, is the property `required`
    buys and this asserts.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    schema = json.loads((copy / "values.schema.json").read_text())
    schema["properties"]["tls"]["required"] = []
    schema["properties"]["taskDb"]["properties"]["tls"]["required"] = []
    (copy / "values.schema.json").write_text(json.dumps(schema))

    result = subprocess.run(
        ["helm", "lint", "--strict", str(copy)], capture_output=True, text=True
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        "dropping `required` was expected to STAY red, for a DIFFERENT "
        f"reason than the schema's own (see docstring): {combined}"
    )
    assert "invalid value; expected bool" in combined, (
        "the ERROR was expected to degrade to sprig's own ternary type error "
        f"once `required` no longer makes absence an ERROR: {combined}"
    )
    assert "`tls.enabled` is absent" not in result.stdout, (
        "this chart's own named sentence must NOT be the ERROR-level message "
        f"any more — lint only logs it as INFO: {result.stdout}"
    )


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
