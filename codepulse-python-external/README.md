# Code Pulse — External Python analysis development build

**Important:** This is not the final 77-rule backward-compatible release. See [RELEASE_STATUS.md](RELEASE_STATUS.md) and [MIGRATION_STATUS.csv](MIGRATION_STATUS.csv).

## Install on Windows

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
$env:CODEPULSE_CONFIG = (Resolve-Path .\config\codepulse.yaml).Path
codepulse --version
```

## Run without modifying the repository

```powershell
codepulse review --repo C:\work\gitfolio --branch test/vuln-scan --base origin/main --no-store
codepulse review --repo C:\work\gitfolio --files src/app.py --no-store
codepulse db upgrade --repo C:\work\gitfolio
codepulse review --repo C:\work\gitfolio --all --store
```

Edit external YAML rule packs in `rule-packs/core` and `rule-packs/custom`. See [RULE_AUTHORING.md](RULE_AUTHORING.md). CLI commands are unchanged, but exact findings and fingerprints are not guaranteed backward-compatible.
