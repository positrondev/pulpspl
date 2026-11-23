# Code Pulse — External-only Python build (intermediate, not 77-rule parity release)

This distribution contains **no** `src/codepulse/rules` folder and no installed built-in rule entry point.
Rules are read from external YAML files only. The source scanner and reports are an implementation detail.

**Migration disclaimer:** This is not a certified replacement for all original 77 checks. See
`MIGRATION_STATUS.csv` for individual rule coverage. Some YAML definitions are intentionally disabled
until accuracy tests are completed. This distribution has 37/77 original IDs, with 40 still missing and zero comprehensive parity certifications. Do not treat absent findings as evidence that all 77 checks ran.

## 1. Install on Windows

Requires Python 3.12+ and Git.

1. Extract this archive to `C:\tools\codepulse-python-external`.
2. Open PowerShell:

```powershell
cd C:\tools\codepulse-python-external
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
codepulse --version
codepulse review --help
```

The Python installation can run the CLI without an executable installer.

## 2. Configure central rules

The supplied `config\codepulse.yaml` is relative to its own directory and currently contains:

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

Set the environment variable **in the PowerShell session** (or persist it in your user environment):

```powershell
$env:CODEPULSE_CONFIG = 'C:\tools\codepulse-python-external\config\codepulse.yaml'
```

All rules, results and the default SQLite store live in Code Pulse-owned folders.
The target repository does not need Code Pulse files.

## 3. Clone or use Gitfolio without changing its configuration

```powershell
cd C:\work
git clone https://github.com/YOUR-ORG/gitfolio.git
cd gitfolio
git fetch origin
```

Replace the example URL with your repository's URL. If already cloned, omit the clone.

## 4. Run reviews (original commands)

```powershell
codepulse review --branch test/vuln-scan --base origin/main --no-store --format md,json,html,csv,sarif
codepulse review --all --store --format md,json,html,csv,sarif
codepulse rules --format json
```

Alternatively run from the Code Pulse folder using `--repo C:\work\gitfolio`.
Reports appear at `C:\tools\codepulse-python-external\reports\latest\` and SQLite
under `C:\tools\codepulse-python-external\data\`.

A source repository is **read-only** to Code Pulse. Any test files you deliberately add to a
feature branch are your own Git changes; Code Pulse doesn't write them.

## 5. Add a rule

Create `rule-packs\custom\company.yaml`:

```yaml
schema_version: 1
pack:
  id: company-security
  version: "1.0.0"
rules:
  - id: CP200.no-eval
    name: Do not evaluate dynamic Python code
    languages: [python]
    severity: high
    component: other
    enabled: true
    match:
      type: python_ast
      node: Call
      where:
        callee: eval
    message: Avoid using eval() on potentially untrusted input.
    remediation: Use explicit parsing and validation instead.
```

Run `codepulse review --all --no-store`. New YAML rule files are loaded on every invocation.
No rebuild is needed. Update an existing rule by editing the YAML fields. Disable it using
`enabled: false`; delete it by deleting its YAML rule entry. Deleting a rule does not
automatically delete historical findings already in the store.

The `python_ast` matcher supports structural predicates such as `callee`, `callee_regex`,
`callee_glob`, `keyword_absent`, `keyword_present`, `under_async`, `under_loop`,
`ancestor`, `source_regex`, `has_call`, `all`, `any`, and `not`. See `EXTERNAL_ONLY_USER_GUIDE.md`.

## 6. Important limitations

- A YAML rule can be syntactically valid without being equivalent to its legacy counterpart.
- Cross-file, data-flow and deep framework-specific checks are not fully migrated.
- The current interpreter handles syntactic source matching; it does not execute arbitrary YAML code.
- Regex rules must be trusted and reviewed; there are not yet hard per-pattern execution limits.
- Phase 1B external-only source scanning currently supports Python AST plus text rules for the other supported languages.
- The `--files` option uses the same file resolution semantics as the existing CLI; give file paths relative to the shell's working directory.
