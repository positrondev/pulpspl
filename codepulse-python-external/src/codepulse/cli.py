"""Command-line entry point. Exit codes: 0 analysis completed (findings or not), 2 usage/config."""

import argparse
import os
import sys
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path

import yaml

from codepulse import __version__
from codepulse.adapters.baseline import read_baseline
from codepulse.adapters.dashboard_html import render_dashboard_html, render_dashboard_json
from codepulse.adapters.eval_io import (
    load_corpus,
    read_record,
    render_eval_json,
    render_eval_markdown,
)
from codepulse.adapters.git_classification import GitAttributesClassification
from codepulse.adapters.git_cli import GitCliSource
from codepulse.adapters.ingest import INGEST_TOOLS, read_report
from codepulse.adapters.plugins import discover_packs
from codepulse.adapters.report_csv import render_csv
from codepulse.adapters.report_html import render_html
from codepulse.adapters.report_json import render_envelope, render_json
from codepulse.adapters.report_markdown import render_markdown
from codepulse.adapters.report_sarif import render_sarif
from codepulse.adapters.semantic_files import FileVerdictCache, JsonlEgressLog
from codepulse.adapters.semantic_http import OpenAICompatibleBackend
from codepulse.adapters.sonarqube import SonarQubeAdapter
from codepulse.adapters.static_classification import StaticClassification
from codepulse.adapters.store_sql import SqlFindingStore, make_engine, upgrade
from codepulse.adapters.trends import build_trends, render_trends_json, render_trends_markdown
from codepulse.adapters.yaml_config import load_config
from codepulse.core.config import Config, DEFAULT_STORE_URL
from codepulse.external_rules.loader import load_rules
from codepulse.external_rules.builtin_metadata import with_builtin_metadata
from codepulse.core.dashboard import build_dashboard
from codepulse.core.delta import Baseline
from codepulse.core.errors import CodePulseError, ConfigError
from codepulse.core.evaluation import Targets, score
from codepulse.core.external import ExternalIssue, IngestNote
from codepulse.core.governance import flag_noisy, override_yaml, per_window, windows
from codepulse.core.lifecycle import IssueStatus, RejectReason, Triage
from codepulse.core.model import Severity
from codepulse.core.pipeline import run_review
from codepulse.core.ports import ClassificationPort
from codepulse.core.registry import RuleRegistry
from codepulse.core.report import AnalysisReport, RunEnvelope
from codepulse.core.resolver import Target
from codepulse.core.semantic import SemanticBackendPort, SemanticOptions, SemanticStage
from codepulse.core.serialization import canonical_json
from codepulse.core.sweep import SweepResult, parse_manifest, render_rollup_markdown, rollup

EXIT_OK = 0
EXIT_USAGE = 2
FORMATS = ("md", "json", "sarif", "html", "csv")
DEFAULT_FORMATS = ("md", "json")
DEFAULT_CONFIG_NAME = "codepulse.yaml"
OUTPUT_NAMES = {
    "md": "report.md",
    "json": "findings.json",
    "sarif": "findings.sarif",
    "html": "report.html",
    "csv": "findings.csv",
}
ENVELOPE_NAME = "run.json"


def _formats(value: str) -> list[str]:
    chosen = [v.strip() for v in value.split(",") if v.strip()]
    bad = sorted(set(chosen) - set(FORMATS))
    if bad or not chosen:
        listed = ", ".join(bad) or "<empty>"
        raise argparse.ArgumentTypeError(
            f"unsupported format(s): {listed}; choose from {', '.join(FORMATS)}"
        )
    return chosen


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codepulse",
        description="Read-only, non-gating review analyzer for Python agentic stacks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="analyze a branch diff, full repo, or file list")
    review.add_argument("--repo", type=Path, default=Path(), help="repository root (default: .)")
    target = review.add_mutually_exclusive_group(required=True)
    target.add_argument("--branch", help="review changes on BRANCH relative to --base")
    target.add_argument("--all", action="store_true", help="review the full repository")
    target.add_argument("--files", nargs="+", metavar="PATH", help="review an explicit file list")
    review.add_argument("--base", help="diff base (default: config base_ref, origin/main)")
    review.add_argument(
        "--config", type=Path, help=f"config file (default: <repo>/{DEFAULT_CONFIG_NAME})"
    )
    review.add_argument("--output", type=Path, help="output directory (default: config output_dir)")
    review.add_argument(
        "--format",
        dest="formats",
        type=_formats,
        default=list(DEFAULT_FORMATS),
        help="comma-separated: md,json,sarif,html,csv (default: md,json)",
    )
    review.add_argument(
        "--ingest",
        action="append",
        default=[],
        metavar="TOOL=PATH",
        help=f"fold an existing tool report into the review ({', '.join(INGEST_TOOLS)})",
    )
    review.add_argument(
        "--sonarqube",
        action="store_true",
        help="fetch open SonarQube issues for the branch (needs `sonarqube:` config)",
    )
    stored = review.add_mutually_exclusive_group()
    stored.add_argument(
        "--store",
        action="store_true",
        help="record the run and reconcile issues (default unless store.enabled: false)",
    )
    stored.add_argument("--no-store", action="store_true", help="do not record this run")
    review.add_argument(
        "--baseline",
        type=Path,
        help="previous findings.json to report new/fixed findings against "
        "(default with --store: the last stored run on the same ref)",
    )

    def repo_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--repo", type=Path, default=Path(), help="repository root (default: .)")
        p.add_argument("--config", type=Path, help="config file (default: <repo>/codepulse.yaml)")

    db = sub.add_parser("db", help="findings store maintenance")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    repo_opts(db_sub.add_parser("upgrade", help="apply findings-store migrations"))

    triage = sub.add_parser("triage", help="record a reviewer decision on an issue")
    repo_opts(triage)
    triage.add_argument("fingerprint", help="issue fingerprint (unique prefix of 8+ chars)")
    triage.add_argument("--status", required=True, choices=[str(s) for s in IssueStatus])
    triage.add_argument("--by", required=True, help="who is making the decision")
    triage.add_argument("--reason", choices=[str(r) for r in RejectReason])
    triage.add_argument("--justification")
    triage.add_argument("--until", type=date.fromisoformat, help="waiver expiry, YYYY-MM-DD")
    triage.add_argument("--evidence", help="link or reference supporting the decision")

    issues = sub.add_parser("issues", help="list issues in the findings store")
    repo_opts(issues)
    issues.add_argument("--status", choices=[str(s) for s in IssueStatus])

    trends = sub.add_parser("trends", help="trends and rule calibration from the findings store")
    repo_opts(trends)
    trends.add_argument("--runs", type=int, default=10)
    trends.add_argument("--format", dest="trend_format", choices=["md", "json"], default="md")

    calibrate = sub.add_parser("calibrate", help="flag sub-checks reviewers keep rejecting")
    repo_opts(calibrate)
    calibrate.add_argument("--window-days", type=int, default=30)
    calibrate.add_argument("--windows", type=int, default=2)
    calibrate.add_argument("--threshold", type=float, default=0.7)
    calibrate.add_argument("--min-decisions", type=int, default=5)
    calibrate.add_argument(
        "--all-repositories", action="store_true", help="pool decisions across repos"
    )
    calibrate.add_argument("--format", dest="cal_format", choices=["md", "json"], default="md")

    rules = sub.add_parser("rules", help="list sub-checks and their effective configuration")
    repo_opts(rules)
    rules.add_argument("--format", dest="rules_format", choices=["md", "json"], default="md")

    dash = sub.add_parser("dashboard", help="write the static HTML dashboard from the store")
    repo_opts(dash)
    dash.add_argument("--output", type=Path, help="directory (default: dashboard_dir)")
    dash.add_argument("--runs", type=int, default=20, help="runs per repository in trends")

    ev = sub.add_parser("eval", help="measure semantic sub-checks against a labelled corpus")
    ev.add_argument("--corpus", type=Path, required=True, help="corpus .yaml file or directory")
    ev.add_argument("--config", type=Path, help="codepulse.yaml (default: ./codepulse.yaml)")
    ev.add_argument("--repo", type=Path, default=Path(), help=argparse.SUPPRESS)
    ev.add_argument("--output", type=Path, default=Path(".codepulse/eval"))
    defaults = Targets()
    ev.add_argument("--min-precision", type=float, default=defaults.min_precision)
    ev.add_argument("--min-recall", type=float, default=defaults.min_recall)
    ev.add_argument("--min-cases", type=int, default=defaults.min_cases)

    sweep = sub.add_parser("sweep", help="review a portfolio of repositories from a manifest")
    sweep.add_argument("--manifest", type=Path, required=True)
    sweep.add_argument("--output", type=Path, default=Path(".codepulse/sweep"))
    sweep_store = sweep.add_mutually_exclusive_group()
    sweep_store.add_argument("--store", action="store_true")
    sweep_store.add_argument("--no-store", action="store_true")
    sweep.add_argument("--format", dest="formats", type=_formats, default=["json"])
    return parser


def _resolve_config(args: argparse.Namespace) -> Config:
    """Explicit --config wins, then CODEPULSE_CONFIG, then repo default.

    Central config paths are relative to the configuration file, not target source.
    """
    env_path = os.environ.get("CODEPULSE_CONFIG")
    selected = args.config if args.config is not None else (Path(env_path) if env_path else None)
    if selected is None:
        default = args.repo / DEFAULT_CONFIG_NAME
        selected = default if default.is_file() else None
    if selected is None:
        return Config()
    selected = selected.expanduser().resolve()
    conf = load_config(selected)
    if conf.external_rules.mode != "external_only":
        return conf
    home = selected.parent
    rules = replace(conf.external_rules, directories=tuple(
        str((home / d).resolve()) if not Path(d).is_absolute() else d
        for d in conf.external_rules.directories
    ))
    def directory(path: str) -> str:
        return str((home / path).resolve()) if not Path(path).is_absolute() else path
    # Always write to Code Pulse-owned directories in isolated mode.
    store = conf.store
    if store.url_env is None and store.url == DEFAULT_STORE_URL:
        db_file = (home / '../data/codepulse.db').resolve().as_posix()
        store = replace(store, url='sqlite:///' + db_file)
    return replace(conf, external_rules=rules, store=store,
                   output_dir=directory(conf.output_dir),
                   dashboard_dir=directory(conf.dashboard_dir))


def _registry_for(config: Config, repo: Path) -> RuleRegistry:
    mode = config.external_rules.mode
    if mode != "external_only":
        raise CodePulseError("This external-only distribution requires external_rules.mode: external_only in the central config")
    rules = load_rules(repo, config.external_rules.directories,
                       allow_external_paths=(mode == "external_only")) if config.external_rules.enabled else ()
    packs = []  # External-only release never discovers executable Python rule packs.
    registry = RuleRegistry.build(packs, config, rules)
    if mode == "external_only" and not registry.external_rules:
        raise CodePulseError("external_only: no enabled executable rules found")
    return registry


def _target(args: argparse.Namespace, repo: Path) -> Target:
    if args.branch:
        return Target.branch(args.branch, args.base)
    if args.all:
        return Target.all()
    rel = []
    for raw in args.files:
        requested = Path(raw)
        full = (requested if requested.is_absolute() else repo / requested).resolve()
        if not full.is_relative_to(repo):
            raise CodePulseError(f"{raw}: outside the repository {repo}")
        rel.append(full.relative_to(repo).as_posix())
    return Target.file_list(rel)


def _legacy_system_prompt(config: Config) -> str:
    return "Code review findings must be supported by source evidence."


def _semantic_stage(config: Config, registry: RuleRegistry) -> SemanticStage:
    sc = config.semantic
    backend: SemanticBackendPort | None = None
    if sc.backend == "openai_compatible":
        backend = OpenAICompatibleBackend(sc)
    return SemanticStage(
        backend,
        system_prompt=_legacy_system_prompt(config),
        templates=registry.prompts,
        remediation={s.id: registry.meta(s.id).remediation for s in registry.active},
        options=SemanticOptions(
            sc.min_confidence, sc.max_tokens, sc.token_budget, sc.redact_patterns
        ),
        cache=FileVerdictCache(Path(sc.cache_dir)) if backend else None,
        egress=JsonlEgressLog(Path(sc.egress_log)) if backend else None,
    )


def _external(
    args: argparse.Namespace, config: Config, repo: Path
) -> tuple[list[ExternalIssue], list[IngestNote]]:
    issues: list[ExternalIssue] = []
    notes: list[IngestNote] = []
    for spec in args.ingest:
        tool, sep, path = spec.partition("=")
        if not sep or tool not in INGEST_TOOLS or not path:
            raise CodePulseError(
                f"--ingest {spec!r}: expected TOOL=PATH with TOOL in {INGEST_TOOLS}"
            )
        found = read_report(tool, Path(path), repo)
        issues += found
        notes.append(IngestNote(tool, "ok", len(found), Path(path).name))
    if args.sonarqube:
        if config.sonarqube is None:
            raise CodePulseError("--sonarqube needs a `sonarqube:` section in codepulse.yaml")
        sq = config.sonarqube
        found, note = SonarQubeAdapter(
            sq.base_url, sq.project_key, sq.token_env, branch_analysis=sq.edition != "community"
        ).fetch_issues(args.branch)
        issues += found
        notes.append(note)
    return issues, notes


def _summary_line(report: AnalysisReport, out_dir: Path) -> str:
    s = report.summary()
    sev = s["by_severity"]
    counts = ", ".join(f"{sev[str(x)]} {x}" for x in Severity if sev[str(x)])
    return (
        f"CodePulse: {s['findings_total']} findings ({counts or 'none'}) · "
        f"{s['files_analyzed']} files analyzed, {s['files_skipped']} skipped · "
        f"{s['needs_review']} need review · report: {out_dir}"
    )


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    repo: Path
    config: Config
    target: Target
    out_dir: Path
    formats: tuple[str, ...]
    store: bool = False
    external: tuple[ExternalIssue, ...] = ()
    notes: tuple[IngestNote, ...] = ()
    baseline: Path | None = None


RENDERERS = {
    "md": render_markdown,
    "json": render_json,
    "sarif": render_sarif,
    "html": render_html,
    "csv": render_csv,
}


def _store_enabled(args: argparse.Namespace, config: Config) -> bool:
    return bool(args.store) or (config.store.enabled and not args.no_store)


def _classifier(
    config: Config, repo: Path, source: GitCliSource, ref: str | None
) -> ClassificationPort:
    """The configured classification source (spec 009 FR-905). `chain` lets git
    attributes label files and falls back to the config's path rules for the rest."""
    cls = config.classification
    static = StaticClassification(cls)
    if cls.source == "static":
        return static
    fallback = static if cls.source == "chain" else StaticClassification(replace(cls, rules=()))
    return GitAttributesClassification(
        repo, cls.attribute, source.tracked_files(ref), fallback, ref
    )


def _baseline(req: ReviewRequest) -> Baseline | None:
    if req.baseline is not None:
        return read_baseline(req.baseline)
    if req.store:
        ref = req.target.head or str(req.target.kind)
        return _store(req.config).previous_baseline(req.repo.name, ref)
    return None


def execute_review(req: ReviewRequest) -> tuple[AnalysisReport, str]:
    """One review, end to end: analyze, write outputs and the envelope, optionally store.
    Shared by `review` and `sweep` so both behave identically."""
    started = datetime.now(UTC)
    t0 = time.perf_counter()
    if not req.repo.is_dir():
        raise CodePulseError(f"repository not found: {req.repo}")
    registry = _registry_for(req.config, req.repo)
    source = GitCliSource(req.repo)
    outcome = run_review(
        req.target,
        source=source,
        classifier=_classifier(req.config, req.repo, source, req.target.head),
        config=req.config,
        registry=registry,
        repository=req.repo.name,
        today=started.date(),
        tool_version=__version__,
        semantic=_semantic_stage(req.config, registry),
        external=req.external,
        ingest_notes=req.notes,
        baseline=_baseline(req),
        validation_record=read_record(req.config.semantic.validation_record),
    )
    report = outcome.report
    req.out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in req.formats:
        name = OUTPUT_NAMES[fmt]
        (req.out_dir / name).write_text(RENDERERS[fmt](report), encoding="utf-8")
        written.append(name)
    base = report.target.base
    envelope = RunEnvelope(
        run_id=str(uuid.uuid4()),
        tool_version=__version__,
        started_at=started.isoformat(timespec="microseconds"),
        completed_at=datetime.now(UTC).isoformat(timespec="microseconds"),
        duration_ms=round((time.perf_counter() - t0) * 1000),
        head_sha=source.commit_of(req.target.head or "HEAD"),
        base_sha=source.commit_of(base) if base else None,
        output_files=tuple(written),
        semantic_calls=outcome.semantic.backend_calls,
        semantic_cache_hits=outcome.semantic.cache_hits,
        semantic_tokens=outcome.semantic.tokens_used,
    )
    (req.out_dir / ENVELOPE_NAME).write_text(render_envelope(envelope), encoding="utf-8")
    stored = ""
    if req.store:
        rec = _store(req.config).record_run(report, envelope, registry, started.date())
        page = write_dashboard(req.config, Path(req.config.dashboard_dir).resolve())
        stored = (
            f" · store: {rec.created} new, {rec.resolved} resolved, {rec.reopened} reopened"
            + (f", {rec.waivers_expired} waivers expired" if rec.waivers_expired else "")
            + f" · dashboard: {page}"
        )
    return report, stored


def _review(args: argparse.Namespace) -> int:
    try:
        repo = args.repo.resolve()
        config = _resolve_config(args)
        external, notes = _external(args, config, repo)
        out_dir = (args.output or Path(config.output_dir)).resolve()
        report, stored = execute_review(
            ReviewRequest(
                repo,
                config,
                _target(args, repo),
                out_dir,
                tuple(args.formats),
                _store_enabled(args, config),
                tuple(external),
                tuple(notes),
                args.baseline,
            )
        )
    except (CodePulseError, ValueError, OSError) as exc:
        print(f"codepulse: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(_summary_line(report, out_dir) + stored)
    return EXIT_OK


def _eval(args: argparse.Namespace) -> int:
    """Run the configured semantic backend over labelled cases (APDD §12). Non-gating:
    exit 0 whenever the evaluation completes, pass or fail."""
    try:
        config = _resolve_config(args)
        registry = _registry_for(config, args.repo.resolve())
        known = sorted(registry.prompts)
        cases = load_corpus(args.corpus, known)
        stage = _semantic_stage(config, registry)
        metas = {sid: registry.meta(sid) for sid in known}
        result = stage.run(
            c.to_candidate(metas[c.subcheck_id].severity, metas[c.subcheck_id].component)
            for c in cases
        )
        targets = Targets(args.min_precision, args.min_recall, args.min_cases)
        report = score(cases, result, stage.backend_label, targets)
    except (CodePulseError, ValueError, OSError) as exc:
        print(f"codepulse: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "eval.json").write_text(render_eval_json(report), encoding="utf-8")
    (out / "eval.md").write_text(render_eval_markdown(report), encoding="utf-8")
    note = " (null backend: nothing evaluated)" if stage.backend_label == "null" else ""
    print(
        f"CodePulse eval: {len(report.passed)} of {len(report.metrics)} sub-checks meet "
        f"targets · {report.cases} cases{note} · report: {out}"
    )
    return EXIT_OK


def write_dashboard(config: Config, out: Path, runs: int = 20) -> Path:
    """Rebuild dashboard.html/json from the store (spec 009 FR-908)."""
    store = _store(config)
    today = date.today()
    data = build_dashboard(
        [
            (name, store.issue_details(name), build_trends(store, name, runs, today))
            for name in store.repositories()
        ]
    )
    out.mkdir(parents=True, exist_ok=True)
    (out / "dashboard.json").write_text(render_dashboard_json(data), encoding="utf-8")
    page = out / "dashboard.html"
    page.write_text(render_dashboard_html(data), encoding="utf-8")
    return page


def _dashboard(args: argparse.Namespace) -> int:
    try:
        config = _resolve_config(args)
        page = write_dashboard(
            config, (args.output or Path(config.dashboard_dir)).resolve(), args.runs
        )
    except (CodePulseError, ValueError, OSError) as exc:
        print(f"codepulse: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"CodePulse dashboard: {page}")
    return EXIT_OK


def _store(config: Config) -> SqlFindingStore:
    engine = make_engine(config.store.resolve_url(os.environ))
    if config.store.auto_migrate:
        upgrade(engine)  # idempotent: the default local store just works
    return SqlFindingStore(engine)


def _store_command(args: argparse.Namespace) -> int:
    try:
        repo = args.repo.resolve()
        config = _resolve_config(args)
        if args.command == "db":
            head = upgrade(make_engine(config.store.resolve_url(os.environ)))
            print(f"codepulse: findings store at revision {head}")
            return EXIT_OK
        store = _store(config)
        today = datetime.now(UTC).date()
        if args.command == "triage":
            t = Triage(
                args.fingerprint,
                IssueStatus(args.status),
                args.by,
                RejectReason(args.reason) if args.reason else None,
                args.justification,
                args.until,
                args.evidence,
            )
            fp, previous = store.triage(repo.name, t, today)
            print(f"codepulse: {fp} {previous} -> {t.status} (by {args.by})")
        elif args.command == "issues":
            rows = store.issues(repo.name, IssueStatus(args.status) if args.status else None)
            for r in rows:
                cols = (r["fingerprint"], f"{r['status']:<11}", f"{r['severity']:<8}")
                print("  ".join(cols), f"{r['subcheck_id']:<34}", r["path"])
            print(f"{len(rows)} issue(s)")
        elif args.command == "trends":
            data = build_trends(store, repo.name, args.runs, today)
            render = render_trends_json if args.trend_format == "json" else render_trends_markdown
            print(render(data), end="")
        else:
            print(
                _calibration(args, store, None if args.all_repositories else repo.name, today),
                end="",
            )
    except (CodePulseError, ValueError, OSError) as exc:
        print(f"codepulse: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "review":
        return _review(args)
    if args.command == "sweep":
        return _sweep(args)
    if args.command == "rules":
        return _rules(args)
    if args.command == "eval":
        return _eval(args)
    if args.command == "dashboard":
        return _dashboard(args)
    return _store_command(args)


def _calibration(
    args: argparse.Namespace, store: SqlFindingStore, repository: str | None, today: date
) -> str:
    spans = windows(today, args.window_days, args.windows)
    stats = per_window(store.decisions(repository), spans)
    flags = flag_noisy(stats, args.threshold, args.min_decisions)
    if args.cal_format == "json":
        return canonical_json(
            {
                "windows": [[s.isoformat(), e.isoformat()] for s, e in spans],
                "threshold": args.threshold,
                "min_decisions": args.min_decisions,
                "subchecks": {
                    sub: [
                        {
                            "decisions": w.decisions,
                            "acted": w.acted,
                            "rejected": w.rejected,
                            "waived": w.waived,
                            "confirmation_rate": w.confirmation_rate,
                        }
                        for w in ws
                    ]
                    for sub, ws in stats.items()
                },
                "flagged": [f.subcheck_id for f in flags],
                "suggested_override": override_yaml(flags),
            }
        )
    head = " | ".join(f"{s.isoformat()}..{e.isoformat()}" for s, e in spans)
    out = [
        "# CodePulse calibration",
        "",
        f"Threshold {args.threshold:.0%} over {args.windows} windows of {args.window_days} days; "
        f"at least {args.min_decisions} reviewer decisions per window.",
        "",
        f"| Sub-check | {head} |",
        "|---|" + "---|" * len(spans),
    ]
    for sub, ws in stats.items():
        cells = " | ".join(
            "—" if w.confirmation_rate is None else f"{w.confirmation_rate:.0%} ({w.decisions})"
            for w in ws
        )
        out.append(f"| `{sub}` | {cells} |")
    out.append("")
    if flags:
        out += [
            f"**{len(flags)} sub-check(s) flagged for revision.** After reviewing each rule, "
            "apply in codepulse.yaml (CodePulse never changes configuration itself):",
            "",
            "```yaml",
            override_yaml(flags).rstrip("\n"),
            "```",
        ]
    else:
        out.append("No sub-check is below threshold for every window.")
    return "\n".join(out) + "\n"


def _rules(args: argparse.Namespace) -> int:
    try:
        config = _resolve_config(args)
        registry = _registry_for(config, args.repo.resolve())
    except CodePulseError as exc:
        print(f"codepulse: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    rows = [
        {
            "subcheck_id": m.id,
            "rule": f"{m.rule_id} {m.rule_name}",
            "detection": str(m.detection),
            "severity": str(m.severity),
            "enabled": m.enabled,
            "experimental": m.experimental,
            "implemented": registry.is_implemented(m.id),
            "has_prompt": m.id in registry.prompts,
        }
        for m in registry.all_metas()
    ]
    if args.rules_format == "json":
        print(canonical_json({"registry_version": registry.version, "subchecks": rows}), end="")
        return EXIT_OK
    print(f"# CodePulse rules — `{registry.version}`\n")
    print("| Sub-check | Detection | Severity | Enabled | Notes |")
    print("|---|---|---|---|---|")
    for r in rows:
        notes = ", ".join(
            n
            for n, on in (
                ("experimental", r["experimental"]),
                ("not implemented", not r["implemented"]),
                ("prompt", r["has_prompt"]),
            )
            if on
        )
        enabled = "yes" if r["enabled"] else "no"
        print(
            f"| `{r['subcheck_id']}` | {r['detection']} | {r['severity']} | {enabled} | {notes} |"
        )
    print(f"\n{sum(1 for r in rows if r['enabled'])} of {len(rows)} sub-checks enabled")
    return EXIT_OK


def _sweep(args: argparse.Namespace) -> int:
    try:
        manifest_path = args.manifest.resolve()
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        entries = parse_manifest(data, str(args.manifest))
    except (OSError, yaml.YAMLError) as exc:
        print(f"codepulse: error: cannot read manifest: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConfigError as exc:
        print(f"codepulse: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    out_root = args.output.resolve()
    results = []
    for entry in entries:
        repo = (manifest_path.parent / entry.path).resolve()
        try:
            cfg_path = (
                (manifest_path.parent / entry.config)
                if entry.config
                else repo / DEFAULT_CONFIG_NAME
            )
            config = load_config(cfg_path) if cfg_path.is_file() or entry.config else Config()
            report, _ = execute_review(
                ReviewRequest(
                    repo,
                    config,
                    Target.all(),
                    out_root / entry.name,
                    tuple(args.formats),
                    _store_enabled(args, config),
                )
            )
            results.append(SweepResult(entry, report))
        except (CodePulseError, ValueError, OSError) as exc:
            results.append(SweepResult(entry, None, str(exc)))  # one bad repo never stops the sweep
    summary = rollup(results)
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "sweep.json").write_text(canonical_json(summary), encoding="utf-8")
    (out_root / "sweep.md").write_text(render_rollup_markdown(summary), encoding="utf-8")
    print(
        f"CodePulse sweep: {summary['succeeded']} reviewed, {summary['failed']} failed · "
        f"report: {out_root / 'sweep.md'}"
    )
    return EXIT_OK if summary["succeeded"] else EXIT_USAGE
