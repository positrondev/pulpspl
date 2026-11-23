# External rule authoring — Python-only development build

## Principle

Users maintain rules in `rule-packs/core/*.yaml` and `rule-packs/custom/*.yaml` under the Code Pulse installation. Never place Code Pulse files in your application repository.

## Manage rules

- **Add:** append a unique `CPnnn.your-rule` entry to a YAML file in `rule-packs/custom`.
- **Update:** edit `match`, `message`, `remediation` or `severity` and save; rerun the original CLI.
- **Disable:** set `enabled: false` in the rule entry.
- **Delete:** remove the rule entry from YAML (or remove a whole custom rule pack file).
- **Validate loaded metadata:** `codepulse rules --format json` with `CODEPULSE_CONFIG` configured.

## Example — configurable Python syntax rule

```yaml
schema_version: 1
pack: {id: my-team-python, version: '1.0'}
rules:
  - id: CP500.no-raw-print
    name: Avoid bare print
    languages: [python]
    severity: medium
    component: other
    detection: deterministic
    enabled: true
    match:
      type: python_ast
      node: Call
      where:
        resolved_callee_regex: '^print$'
    message: Use structured logging instead of print.
    remediation: Use an approved application logger.
```

## Example — intra-function flow rule

```yaml
schema_version: 1
pack: {id: my-team-flow, version: '1.0'}
rules:
  - id: CP501.llm-output-sql
    name: Model output reaches SQL execution
    languages: [python]
    severity: high
    component: database
    detection: heuristic
    enabled: false
    match:
      type: python_flow
      source_calls: ['(?:^|\.)invoke$']
      source_parameters: []
      sink_calls: ['(?:^|\.)execute$']
      sanitizer_calls: ['(?:^|\.)model_validate$']
    message: Possible unvalidated model output in SQL execution.
    remediation: Apply a typed schema and use parameterized queries.
```

**Limitations:** `python_flow` is an intra-procedural, conservative heuristic, not a complete taint analyzer. Regex matchers can be slow for hostile patterns. The presence of YAML for an original rule does not prove parity with its legacy detection.

## Review a repository without touching it

From PowerShell:

```powershell
$env:CODEPULSE_CONFIG = 'C:\tools\codepulse\config\codepulse.yaml'
codepulse review --repo C:\work\gitfolio --branch test/vuln-scan --base origin/main --no-store
codepulse review --repo C:\work\gitfolio --files src/app.py --no-store
codepulse review --repo C:\work\gitfolio --all --store
```

Reports, dashboards and SQLite files use directories in the central configuration file.
