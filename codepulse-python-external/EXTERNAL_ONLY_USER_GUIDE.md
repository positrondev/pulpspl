# Code Pulse — Central external-rule engine (development build)

**Status:** 37 of 77 original checks have executable YAML definitions; 40 are absent, and none is fully parity-certified. See `MIGRATION_STATUS.csv` and `RELEASE_STATUS.md`. The CLI can run real reviews but this build is **not** a comprehensive replacement for the original analyzer.

## Install (Windows PowerShell)

1. Extract the ZIP into `C:\tools\codepulse-external` (you can choose another folder).
2. Open PowerShell:

```powershell
cd C:\tools\codepulse-external
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
codepulse --version
codepulse review --help
```

3. Central configuration is already included at `config\codepulse.yaml`. Make it discoverable in **every new PowerShell session** (the variable avoids changing CLI commands):

```powershell
$env:CODEPULSE_CONFIG = 'C:\tools\codepulse-external\config\codepulse.yaml'
```

Optionally persist it (restart terminal for the new value to take effect):

```powershell
[Environment]::SetEnvironmentVariable('CODEPULSE_CONFIG','C:\tools\codepulse-external\config\codepulse.yaml','User')
```

4. No changes to target repositories. From any working directory, pass `--repo` explicitly:

```powershell
codepulse rules --repo C:\work\gitfolio --format json
codepulse review --repo C:\work\gitfolio --branch test/vuln-scan --base origin/main --no-store
codepulse review --repo C:\work\gitfolio --all --store --format md,json,html,csv,sarif
```

Alternatively `cd C:\work\gitfolio` and use your original CLI command **without** `--repo`:

```powershell
codepulse review --branch test/vuln-scan --base origin/main --no-store
codepulse review --all --store
```

The `CODEPULSE_CONFIG` variable points to central Code Pulse configuration, so Gitfolio does not need `codepulse.yaml`, a rule directory, `.codepulse/`, `.gitignore` edits, or reports. Your own feature-branch test changes remain under your control.

## Where the files live

```text
C:\tools\codepulse-external\
  config\codepulse.yaml            <- user edits
  rule-packs\core\core.yaml        <- user edits / adds / removes rules
  rule-packs\custom\               <- user-authored packs (add folder to config)
  reports\latest\                  <- generated outputs
  reports\dashboard\               <- generated dashboard
  data\codepulse.db                <- stored findings
  src\codepulse\...                <- internal engine (do not edit)

C:\work\gitfolio\                <- only source being analyzed
```

`config\codepulse.yaml`:

```yaml
output_dir: ../reports/latest
dashboard_dir: ../reports/dashboard
store:
  enabled: true
external_rules:
  mode: external_only
  enabled: true
  directories:
    - ../rule-packs/core
    - ../rule-packs/custom
  strict_validation: true
```

Relative rule and report paths resolve relative to `config/codepulse.yaml`, not the Git repository. If you add `../rule-packs/custom`, create that directory first. If `store.url` is absent, the default database is under the Code Pulse `data/` directory in this layout.

## Create a rule (entirely external YAML)

Create `rule-packs/custom/team.yaml`:

```yaml
schema_version: 1
pack:
  id: team-quality
  version: '1.0.0'
rules:
  - id: CP200.no-print
    name: Avoid console printing
    languages: [python, java]
    enabled: true
    severity: medium
    component: other
    match:
      type: regex
      patterns:
        python: '^\s*print\s*\('
        java: '\bSystem\.out\.println\s*\('
    message: Use structured logging instead of printing.
    remediation: Replace this statement with your logger.
```

Add `../rule-packs/custom` to `external_rules.directories` in the central configuration. **No install, rebuild, or repository change is required after this.** Rules reload each CLI invocation.

### Edit

Open the rule YAML and change `severity`, `enabled`, message, remediation, file filters, or `match` predicates; save it and rerun your review.

### Delete

Remove a rule entry from the YAML `rules` list, or remove its YAML pack file, and rerun Code Pulse. It will no longer execute that rule. Deleting a rule from the registry does not automatically delete historical findings from the store; stored run history remains. Review your triage/lifecycle procedures separately.

### AST rules — Python syntax-specific matcher

```yaml
- id: CP201.no-unbounded-result
  name: Future result must have timeout
  languages: [python]
  enabled: true
  severity: medium
  component: other
  match:
    type: python_ast
    node: Call
    where:
      all:
        - callee_glob: '*.result'
        - keyword_absent: timeout
  message: Future.result() has no timeout.
  remediation: Add a timeout and handle the exception.
```

Match types supported: `text`, `regex`, `python_ast`. Python AST predicates are declarative `all`, `any`, `not` combinations of validated keys such as `callee`, `callee_regex`, `callee_glob`, `keyword_absent`, `keyword_present`, `name_regex`, `literal_regex`, `decorator_regex`, `test_name`, `no_assert`, `no_auth`, `bare_except`, `swallow`, `except_return_constant`, `under_with`, `under_loop`, `under_async`, `filename_regex`, `ancestor`, `not_ancestor`, `has_call`, `not_has_call`, `attr`, `value_equals`, `call_arg_regex`, `source_regex`, `node_contains`, `kwargs_any`, `has_assert`. Consult the included example rules. `python_ast` cannot provide true resolved-symbol or interprocedural data-flow semantics. Java currently supports only text and regex rules.

**Important:** `regex` matches source text and may match comments or string literals; write and test patterns carefully. Use only trusted rules, because regexes do not yet have enforced per-match timeouts. Direct user-authored Python code is not accepted in YAML.

## Reports

Run:

```powershell
codepulse review --repo C:\work\gitfolio --all --store --format md,json,html,csv,sarif
```

Read `reports\latest\report.html`, `findings.json`, `report.md`, `findings.csv`, and `findings.sarif`; see `reports\dashboard\dashboard.html`. Running again overwrites the `latest` report files. To keep separate runs, use `--output C:\tools\codepulse-external\reports\gitfolio-test`.

## Check isolation and troubleshooting

1. `codepulse rules --repo C:\work\gitfolio --format json`: only external YAML rules should be listed.
2. `git -C C:\work\gitfolio status --short`: Code Pulse must not have written any files to the target.
3. If a rule isn't listed, check `CODEPULSE_CONFIG`, the rules folder configuration and the YAML syntax.
4. If the branch review reports 0 files, ensure the test commits are on the named branch and `origin/main` has been fetched.
5. `--files` accepts paths whose resolution is inside the target repository; run from that repo root or pass absolute paths.
6. The 77 legacy rules are NOT fully migrated: the missing IDs and migration state are in `MIGRATION_STATUS.csv`. Avoid assuming an absence of findings means an absence of vulnerabilities.
