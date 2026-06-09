# CLAUDE.md — Secaria

Guidance for working in the `secaria/` project. This is a standalone Python
tool that happens to live in a Jekyll site repo; treat `secaria/` as its own
project root.

## What this is

Secaria is an **agentless security posture assessment** toolkit. It collects
facts from infrastructure read-only, evaluates **data-defined rules**, and
renders a report with findings mapped to **MITRE ATT&CK, CIS, and DISA STIG**.

Current scope is a narrow vertical slice: **Active Directory over LDAP**. The
architecture is built to extend to Windows (WinRM/pypsrp), Exchange, and Linux
(SSH/paramiko) without reworking the engine.

## The data flow (know this before changing anything)

```
Target ──► Collector.collect() ──► facts dict ──► Engine.evaluate(rules) ──► [Finding] ──► Score ──► report
```

- **Collectors** (`collectors/`) connect and return a **flat-ish facts dict**.
  They are strictly **read-only** and **never judge**. The facts dict shape is
  a contract — it's documented in the AD collector's module docstring.
- **Rules** (`rules/*.yaml`) are **data**. A rule names a fact path, an
  operator describing the **failing** condition, a threshold, remediation, and
  framework references. `rules/schema.py` loads, validates, and evaluates them.
- **Engine** (`core/engine.py`) is thin: get facts (live collector or `--facts`
  file) and run rules. No domain knowledge lives here.
- **Finding** (`core/finding.py`) is the one normalized shape everything speaks.
- **Scoring** (`core/scoring.py`) is intentionally explainable, not a black box.
- **Reporting** (`reporting/`) renders exec summary + technical detail.

## Hard rules

1. **Collection stays read-only.** No LDAP MODIFY, no remote writes, ever.
2. **Credentials never touch disk.** Read them from env (`SECARIA_*`) or pass
   in memory. `Credential.__repr__` is masked — keep it that way.
3. **Live targets must be authorized.** `Target.require_authorized()` guards
   live collection; the CLI requires `--i-have-authorization`. Don't bypass it.
4. **Add checks as YAML, not Python.** If you're editing the engine to add a
   check, stop — it almost certainly belongs in a rule file. Engine changes are
   for new *operators* or *capabilities*, not new checks.

## Adding a rule

Create `rules/ad/<name>.yaml` (see existing files for the shape). Every rule
must have: unique `id`, `severity`, a `check`, a `recommendation`, and at least
one framework reference. The test suite enforces these. If the rule needs a
fact the collector doesn't emit yet, add the fact to the collector **and**
document it in the collector docstring's facts schema.

Available operators live in `rules/schema.py:_OPERATORS`. Add new ones there
with a one-line lambda; they take `(fact_value, threshold)` and return True
when the control is **failing**.

## Adding a collector (future slices)

Subclass `collectors.base.Collector`, set `kind`, implement `collect()`
read-only, document the facts schema in the docstring, and wire it into
`core/engine.collect_facts()`. Keep live-collection methods importing their
client library (`ldap3`, `pypsrp`, …) lazily so offline evaluation never needs
the dependency.

## Commands

```bash
pip install -e ".[dev]"                     # PyYAML + pytest
pip install -e ".[ad]"                       # ldap3 for live AD
pytest                                       # run tests (offline, no DC needed)
python -m secaria.cli rules                  # list ruleset
python -m secaria.cli scan --facts examples/sample_facts.json --target corp --html /tmp/r.html
```

Offline mode (`--facts FILE`) is the primary way to develop and test — it needs
no domain controller and no network. `examples/sample_facts.json` is a
deliberately-weak domain; `tests/conftest.py` has clean + weak fixtures.

## Conventions

- Python ≥ 3.10, standard library + PyYAML for the core; collection libs are
  optional extras.
- Dataclasses for models; `enum.Enum` for Severity/Status.
- Keep the reporting template dependency-free (string-substituted HTML, not a
  templating engine) so `pip install secaria` stays light.
- Tests must run fully offline. Anything needing a live DC is marked
  `# pragma: no cover` and exercised via captured facts instead.
