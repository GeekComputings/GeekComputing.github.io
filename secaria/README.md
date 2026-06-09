# Secaria

Agentless security **posture assessment**. Secaria connects to your
infrastructure read-only, evaluates a set of data-defined rules, and produces
an executive + technical report with every finding mapped to **MITRE ATT&CK**,
**CIS Benchmarks**, and **DISA STIG**.

This is the first vertical slice: **Active Directory** assessment over LDAP.
Windows (WinRM) and Exchange collectors are planned next.

## Why it's built this way

- **Rules are data, not code.** A check is a YAML file describing a fact to
  inspect, the failing condition, remediation, and framework references. Add
  checks without touching the engine — see `secaria/rules/ad/`.
- **Collectors only gather; rules only judge.** The same facts feed CIS *and*
  STIG rules, so one read-only scan serves multiple compliance lenses.
- **One finding model, three framework lenses.** Reports can pivot between a
  compliance checklist and an adversary-technique view.
- **Safe by default.** Collection is strictly read-only (LDAP SEARCH, never
  MODIFY), credentials never touch disk, and live targets must be explicitly
  marked authorized.

## Install

```bash
cd secaria
pip install -e .            # offline evaluation + reporting
pip install -e ".[ad]"     # add ldap3 for live AD collection
pip install -e ".[dev]"    # add pytest
```

## Use

Offline — evaluate a captured facts file (no domain controller needed):

```bash
secaria scan --facts examples/sample_facts.json --target corp.example.com --html report.html
```

Write a machine-readable **scan record** (metadata + evidence + findings) for
auditing, re-evaluation, and future diffing:

```bash
secaria scan --facts examples/sample_facts.json --target corp.example.com --json scan.json
```

A scan record stores the raw facts it judged, plus provenance (timestamp, tool
and ruleset version, a ruleset fingerprint, collection mode). You can re-run a
newer ruleset over an old record's evidence — pass the record straight back to
`--facts`:

```bash
secaria scan --facts scan.json --target corp.example.com
```

List the loaded ruleset:

```bash
secaria rules
```

Live — read-only LDAP collection (requires authorization + credentials in env):

```bash
export SECARIA_USERNAME=svc-audit SECARIA_PASSWORD=... SECARIA_DOMAIN=corp.example.com
secaria scan --target dc01.corp.example.com --i-have-authorization --html report.html
```

`secaria scan` exits non-zero (2) when any High/Critical findings exist, so it
can gate a pipeline.

## Layout

```
secaria/
├── core/         engine, finding model, target/credentials, scoring
├── collectors/   read-only agentless gatherers (AD over LDAP today)
├── rules/        YAML rule definitions + loader/evaluator (the extensible core)
├── frameworks/   ATT&CK/CIS/STIG reference enrichment
└── reporting/    HTML (exec + technical) and text renderers
```

## Adding a rule

Drop a YAML file in `secaria/rules/ad/`:

```yaml
id: AD-EXAMPLE
title: Short human-readable title
severity: high            # info | low | medium | high | critical
category: active_directory
description: Why this matters.
check:
  fact: password_policy.min_length   # dotted path into the collected facts
  operator: lt                       # the FAILING condition
  value: 14
recommendation: What to do about it.
references:
  attack: ["T1110.003"]
  cis: ["1.1.4"]
  stig: ["V-243478"]
```

Operators: `eq ne gt gte lt lte contains not_contains is_true is_false exists
not_exists count_gt count_gte non_empty`. The fact value of a failing rule
becomes the finding's evidence.

## Test

```bash
pytest
```
