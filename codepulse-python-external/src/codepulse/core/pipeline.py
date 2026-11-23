"""One review run: resolve → analyze → judge candidates → normalize → report."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from typing import Any

from codepulse.core.candidate import Candidate
from codepulse.core.config import Config
from codepulse.core.delta import Baseline, compute_delta
from codepulse.core.engine.index import ProjectIndex, build_index
from codepulse.core.engine.visitor import FileAnalysis, analyze_config_file, analyze_source
from codepulse.core.evaluation import validation_status
from codepulse.core.external import ExternalIssue, ExternalMap, IngestNote, merge, to_findings, parse_external_map
from codepulse.core.globs import compile_globs
from codepulse.core.model import Component, Finding
from codepulse.core.normalizer import SuppressedCandidate, normalize, split_candidates
from codepulse.core.ports import ClassificationPort, SourcePort
from codepulse.core.registry import RuleRegistry
from codepulse.core.report import (
    AnalysisReport,
    IndexSummary,
    ModuleCapabilities,
    ReviewTarget,
)
from codepulse.external_rules.matcher import match_file
from codepulse.core.resolver import FileKind, Resolution, Resolver, Target, TargetKind
from codepulse.core.semantic import SemanticOptions, SemanticResult, SemanticStage

UNRESOLVED_CAP = 100  # spec 006 FR-603; the total is always reported


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    report: AnalysisReport  # deterministic evidence
    semantic: SemanticResult  # carries run-varying stats (calls, cache hits) for the envelope


def run_review(
    target: Target,
    *,
    source: SourcePort,
    classifier: ClassificationPort,
    config: Config,
    registry: RuleRegistry,
    repository: str,
    today: date,
    tool_version: str,
    semantic: SemanticStage | None = None,
    external: Sequence[ExternalIssue] = (),
    ingest_notes: Sequence[IngestNote] = (),
    baseline: Baseline | None = None,
    validation_record: Mapping[str, Any] | None = None,
) -> ReviewOutcome:
    resolver = Resolver(source, classifier, config, registry.external_rules)
    resolution = resolver.resolve(target)
    index, index_summary = _project_index(resolver, target, resolution, config, registry)
    agent_capabilities: tuple[ModuleCapabilities, ...] = ()
    if index is not None:
        agent_capabilities = tuple(
            sorted(
                (caps for _, caps in index.facts("agent_capabilities") if caps is not None),
                key=lambda c: c.path,
            )
        )
    analyses: list[FileAnalysis] = []
    skipped = list(resolution.skipped)
    for f in resolution.files:
        if f.kind is FileKind.PYTHON and config.external_rules.mode == "external_only":
            analysis = FileAnalysis(f.path)
        elif f.kind is FileKind.PYTHON:
            analysis = analyze_source(f.path, f.text, registry, index)
        elif f.kind is FileKind.TOOL_CONFIG:
            analysis = analyze_config_file(f.path, f.text, registry)
        else:
            analysis = FileAnalysis(f.path)
        analysis = match_file(analysis, f.text, registry)
        if analysis.skip is not None:
            skipped.append(analysis.skip)
        else:
            analyses.append(analysis)

    candidates: list[Candidate] = []
    answered: list[SuppressedCandidate] = []
    for a in analyses:
        kept, suppressed = split_candidates(a, today)
        candidates += kept
        answered += suppressed
    stage = semantic or SemanticStage(
        None, system_prompt="", templates={}, remediation={}, options=SemanticOptions()
    )
    judged = stage.run(candidates)
    by_path: dict[str, list[Finding]] = {}
    for judged_finding in judged.findings:
        by_path.setdefault(judged_finding.location.path, []).append(judged_finding)
    analyses = [
        replace(a, findings=(*a.findings, *by_path.get(a.path, ()))) if a.path in by_path else a
        for a in analyses
    ]

    analyses = _fold_external(analyses, external, registry)
    analyzed = {a.path for a in analyses}
    notes = []
    for note in ingest_notes:
        dropped = sum(
            1 for i in external if _tool_family(i.tool) == note.tool and i.path not in analyzed
        )
        detail = note.detail
        if dropped:
            why = f"{dropped} on files not analyzed (gated, excluded, or outside the diff) dropped"
            detail = f"{detail}; {why}" if detail else why
        notes.append(replace(note, detail=detail))
    unresolved = sorted(
        (u for a in analyses for u in a.unresolved), key=lambda u: (u.path, u.line, u.callee)
    )
    analyses = _cap_nonproduction(analyses, config)
    normalized = normalize(analyses, {f.path: f.changed for f in resolution.files}, today)
    base = (target.base or config.base_ref) if target.kind is TargetKind.BRANCH else None
    report = AnalysisReport(
        tool_version=tool_version,
        target=ReviewTarget(repository, target.kind, target.head, base),
        registry_version=registry.version,
        config_hash=config.config_hash(),
        files_analyzed=tuple(sorted(a.path for a in analyses)),
        skipped=tuple(sorted(skipped, key=lambda s: (s.path, s.reason))),
        findings=normalized.findings,
        suppressed=normalized.suppressed,
        suppression_issues=normalized.suppression_issues,
        rule_errors=tuple(
            sorted(
                (e for a in analyses for e in a.rule_errors),
                key=lambda e: (e.path, e.line, e.subcheck_id),
            )
        ),
        unimplemented=registry.unimplemented,
        rule_names=registry.rule_names,
        semantic_backend=stage.backend_label,
        prompt_versions=judged.prompt_versions,
        candidates_total=len(candidates) + len(answered),
        answered=tuple(
            sorted(
                answered, key=lambda s: (s.candidate.location.path, s.candidate.location.start_line)
            )
        ),
        needs_review=judged.unevaluated,
        ingest_notes=tuple(sorted(notes, key=lambda n: n.tool)),
        experimental_skipped=registry.experimental_skipped,
        index=index_summary,
        agent_capabilities=agent_capabilities,
        unresolved=tuple(unresolved[:UNRESOLVED_CAP]),
        unresolved_total=len(unresolved),
        semantic_validation=validation_status(
            validation_record,
            stage.backend_label,
            judged.prompt_versions,
            {pv.split("@", 1)[0] for pv in judged.prompt_versions},
        ),
    )
    if baseline is not None:
        report = replace(report, delta=compute_delta(baseline, report.findings, analyzed))
    return ReviewOutcome(report, judged)


def _cap_nonproduction(analyses: list[FileAnalysis], config: Config) -> list[FileAnalysis]:
    """Findings in tests, examples, docs and scripts keep their sub-check and fingerprint;
    only the severity is capped, so they rank below production code (spec 012)."""
    cap = config.nonproduction_max_severity
    if cap is None:
        return analyses
    nonprod = compile_globs(config.nonproduction_paths)
    out = []
    for a in analyses:
        if nonprod(a.path) is None:
            out.append(a)
            continue
        findings = tuple(
            replace(f, severity=cap) if f.severity.rank < cap.rank else f for f in a.findings
        )
        out.append(replace(a, findings=findings))
    return out


def _project_index(
    resolver: Resolver,
    target: Target,
    resolution: Resolution,
    config: Config,
    registry: RuleRegistry,
) -> tuple[ProjectIndex | None, IndexSummary]:
    if not config.index_enabled:
        return None, IndexSummary(enabled=False, disabled_checks=registry.index_checks)
    if not registry.index_checks:
        return None, IndexSummary(enabled=True)  # nothing would read it: don't read the repo
    files, refused = resolver.index_files(target, resolution)
    index = build_index(files, registry.indexers)
    indexed = len(index.modules)
    return index, IndexSummary(True, indexed, refused, index.skipped)


def _fold_external(
    analyses: list[FileAnalysis], external: Sequence[ExternalIssue], registry: RuleRegistry
) -> list[FileAnalysis]:
    """Map external issues onto analyzed files only, so the classification gate also
    governs what a scanner's message may disclose, then merge corroborating issues."""
    if not external:
        return analyses
    analyzed = {a.path for a in analyses}
    mapping: ExternalMap = registry.catalogs.get("external_map") or parse_external_map([])
    components = {m.rule_id: m.component for m in (registry.meta(s.id) for s in registry.active)}
    remediations = {
        m.rule_id: m.remediation for m in (registry.meta(s.id) for s in registry.active)
    }
    ext = to_findings(
        (i for i in external if i.path in analyzed),
        mapping,
        lambda element: components.get(element, Component.OTHER),
        lambda element: remediations.get(element),
    )
    out = []
    for a in analyses:
        mine = [f for f in ext if f.location.path == a.path]
        if not mine:
            out.append(a)
            continue
        merged, remaining = merge(a.findings, mine)
        out.append(replace(a, findings=(*merged, *remaining)))
    return out


def _tool_family(tool: str) -> str:
    """`sarif:semgrep` issues are reported under the `sarif` source they came from."""
    return tool.split(":", 1)[0]
