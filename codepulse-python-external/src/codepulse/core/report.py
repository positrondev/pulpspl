"""The report model. ``AnalysisReport`` is deterministic evidence; ``RunEnvelope`` holds the
per-run facts (ids, clocks, SHAs) that must never leak into it (Constitution Art. II)."""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from codepulse.core.candidate import Unevaluated
from codepulse.core.delta import Delta
from codepulse.core.engine.visitor import RuleError, UnresolvedCall
from codepulse.core.external import IngestNote
from codepulse.core.model import Detection, Finding, Origin, Severity, SkipReason, SkipRecord
from codepulse.core.normalizer import SuppressedCandidate, SuppressedFinding, SuppressionIssue
from codepulse.core.resolver import TargetKind

SCHEMA = "codepulse.findings/1"


@dataclass(frozen=True, slots=True)
class ReviewTarget:
    repository: str
    mode: TargetKind
    head: str | None = None
    base: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "mode": str(self.mode),
            "head": self.head,
            "base": self.base,
        }


@dataclass(frozen=True, slots=True)
class IndexSummary:
    """What the project index covered (spec 005 FR-504/505)."""

    enabled: bool
    files_indexed: int = 0
    files_not_admitted: int = 0  # gated, excluded, generated, or unreadable
    skipped: tuple[SkipRecord, ...] = ()  # admitted but unparseable, or an indexer crashed
    disabled_checks: tuple[str, ...] = ()  # sub-checks that did not run because it is off

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "files_indexed": self.files_indexed,
            "files_not_admitted": self.files_not_admitted,
            "skipped": [s.to_dict() for s in self.skipped],
            "disabled_checks": list(self.disabled_checks),
        }


@dataclass(frozen=True, slots=True)
class ToolGrant:
    """One tool given to an agent, with its capability class (E16)."""

    name: str
    capability: str  # "code execution" | "shell" | ... | "other"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "capability": self.capability}


@dataclass(frozen=True, slots=True)
class McpServer:
    transport: str
    kind: str  # "remote" (HTTP/SSE) | "stdio" (local process)
    authenticated: bool

    def to_dict(self) -> dict[str, Any]:
        return {"transport": self.transport, "kind": self.kind, "authenticated": self.authenticated}


@dataclass(frozen=True, slots=True)
class AgentSite:
    line: int
    binder: str  # the binding call: bind_tools / ToolNode / create_react_agent / tools=...
    tools: tuple[ToolGrant, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "binder": self.binder,
            "tools": [t.to_dict() for t in self.tools],
        }


@dataclass(frozen=True, slots=True)
class ModuleCapabilities:
    """The agent capability surface of one module (spec 018 bucket D): which agents are given
    which tools, which MCP servers they reach, and whether any approval guard is in scope."""

    module: str
    path: str
    sites: tuple[AgentSite, ...]
    mcp_servers: tuple[McpServer, ...]
    approval_markers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "path": self.path,
            "sites": [s.to_dict() for s in self.sites],
            "mcp_servers": [m.to_dict() for m in self.mcp_servers],
            "approval_markers": list(self.approval_markers),
        }


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    tool_version: str
    target: ReviewTarget
    registry_version: str
    config_hash: str
    files_analyzed: tuple[str, ...]
    skipped: tuple[SkipRecord, ...]
    findings: tuple[Finding, ...]
    suppressed: tuple[SuppressedFinding, ...]
    suppression_issues: tuple[SuppressionIssue, ...]
    rule_errors: tuple[RuleError, ...]
    unimplemented: tuple[str, ...]
    rule_names: Mapping[str, str]
    semantic_backend: str = "null"
    prompt_versions: tuple[str, ...] = ()
    candidates_total: int = 0
    needs_review: tuple[Unevaluated, ...] = ()
    answered: tuple[SuppressedCandidate, ...] = ()  # candidates settled by a justified suppression
    ingest_notes: tuple[IngestNote, ...] = ()
    experimental_skipped: tuple[str, ...] = ()
    index: IndexSummary = IndexSummary(enabled=False)
    delta: Delta | None = None
    unresolved: tuple[UnresolvedCall, ...] = ()  # capped list, sorted
    unresolved_total: int = 0
    semantic_validation: str = "n/a"
    agent_capabilities: tuple[ModuleCapabilities, ...] = ()  # E16 bucket D governance inventory

    def summary(self) -> dict[str, Any]:
        sev = Counter(f.severity for f in self.findings)
        origin = Counter(f.origin for f in self.findings)
        detection = Counter(f.detection for f in self.findings)
        skipped = Counter(s.reason for s in self.skipped)
        return {
            "files_analyzed": len(self.files_analyzed),
            "files_skipped": len(self.skipped),
            "skipped_by_reason": {str(r): skipped[r] for r in SkipReason if skipped[r]},
            "findings_total": len(self.findings),
            "by_severity": {str(s): sev[s] for s in Severity},
            "by_origin": {str(o): origin[o] for o in Origin if origin[o]},
            "by_detection": {str(d): detection[d] for d in Detection if detection[d]},
            "by_rule": dict(sorted(Counter(f.rule_id for f in self.findings).items())),
            "suppressed": len(self.suppressed) + len(self.answered),
            "suppression_issues": len(self.suppression_issues),
            "rule_errors": len(self.rule_errors),
            "semantic_backend": self.semantic_backend,
            "candidates": self.candidates_total,
            "needs_review": len(self.needs_review),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "tool_version": self.tool_version,
            "target": self.target.to_dict(),
            "registry_version": self.registry_version,
            "config_hash": self.config_hash,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [s.to_dict() for s in self.suppressed],
            "suppressed_candidates": [a.to_dict() for a in self.answered],
            "suppression_issues": [i.to_dict() for i in self.suppression_issues],
            "skipped": [s.to_dict() for s in self.skipped],
            "rule_errors": [e.to_dict() for e in self.rule_errors],
            "files_analyzed": list(self.files_analyzed),
            "unimplemented_subchecks": list(self.unimplemented),
            "needs_review": [u.to_dict() for u in self.needs_review],
            "prompt_versions": list(self.prompt_versions),
            "external_sources": [n.to_dict() for n in self.ingest_notes],
            "experimental_skipped": list(self.experimental_skipped),
            "index": self.index.to_dict(),
            "delta": self.delta.to_dict() if self.delta else None,
            "unresolved_calls": {
                "total": self.unresolved_total,
                "listed": [u.to_dict() for u in self.unresolved],
            },
            "semantic_validation": self.semantic_validation,
            "rule_names": dict(sorted(self.rule_names.items())),
            "agent_capabilities": [c.to_dict() for c in self.agent_capabilities],
        }


@dataclass(frozen=True, slots=True)
class RunEnvelope:
    run_id: str
    tool_version: str
    started_at: str  # ISO-8601 UTC
    completed_at: str
    duration_ms: int
    head_sha: str | None
    base_sha: str | None
    output_files: tuple[str, ...]
    semantic_calls: int = 0  # varies with cache state, so it lives here, not in findings.json
    semantic_cache_hits: int = 0
    semantic_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "output_files": list(self.output_files),
            "semantic": {
                "calls": self.semantic_calls,
                "cache_hits": self.semantic_cache_hits,
                "tokens": self.semantic_tokens,
            },
        }
