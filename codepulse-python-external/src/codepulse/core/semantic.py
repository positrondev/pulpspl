"""Candidate-scoped semantic evaluation (APDD §6.3.4). Pure: every side effect is a port.

Flow per candidate: redact → cache key → cache → (budget) → backend → strict parse →
accept or record unevaluated. Nothing is dropped (Constitution Art. VIII).
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from codepulse.core.candidate import Candidate, Unevaluated, UnevaluatedReason
from codepulse.core.errors import CodePulseError
from codepulse.core.model import Detection, Finding, Origin
from codepulse.core.redaction import redact

VERDICTS = frozenset({"violation", "no_violation", "insufficient_context"})


class BackendError(CodePulseError):
    """A backend call failed. ``kind`` is ``timeout`` or ``backend_error``."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class SemanticRequest:
    subcheck_id: str
    prompt_version: str
    system: str
    user: str
    max_tokens: int
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class SemanticResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class SemanticBackendPort(Protocol):
    name: str
    model_id: str

    def evaluate(self, request: SemanticRequest) -> SemanticResponse: ...


class VerdictCachePort(Protocol):
    def get(self, key: str) -> dict[str, Any] | None: ...

    def put(self, key: str, value: dict[str, Any]) -> None: ...


class EgressLogPort(Protocol):
    def record(self, entry: dict[str, Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    subcheck_id: str
    version: int
    text: str

    @property
    def prompt_version(self) -> str:
        digest = hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:8]
        return f"{self.subcheck_id}@v{self.version}+{digest}"

    def render(self, candidate: Candidate, snippet: str) -> str:
        facts = "\n".join(f"- {k}: {v}" for k, v in sorted(candidate.facts.items())) or "- (none)"
        numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(snippet.splitlines()))
        return (
            self.text.replace("{question}", candidate.question)
            .replace("{facts}", facts)
            .replace("{snippet}", numbered)
        )


@dataclass(frozen=True, slots=True)
class Verdict:
    verdict: str
    confidence: float
    rationale: str
    suggested_fix: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "suggested_fix": self.suggested_fix,
        }


def parse_verdict(text: str) -> Verdict:
    """Strict: anything but the documented JSON object is a parse error (ValueError)."""
    body = text.strip()
    if body.startswith("```"):  # tolerate a fenced block, nothing else
        body = body.strip("`").removeprefix("json").strip()
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("verdict must be a JSON object")
    verdict = data.get("verdict")
    confidence = data.get("confidence")
    rationale = data.get("rationale")
    fix = data.get("suggested_fix")
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VERDICTS)}")
    if not isinstance(confidence, int | float) or isinstance(confidence, bool):
        raise ValueError("confidence must be a number")
    if not isinstance(rationale, str):
        raise ValueError("rationale must be a string")
    if fix is not None and not isinstance(fix, str):
        raise ValueError("suggested_fix must be a string or null")
    return Verdict(verdict, max(0.0, min(1.0, float(confidence))), rationale.strip(), fix)


@dataclass(frozen=True, slots=True)
class SemanticOptions:
    min_confidence: float = 0.75
    max_tokens: int = 400
    token_budget: int = 50_000  # per run; estimated input + max output per call
    redact_patterns: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SemanticResult:
    findings: tuple[Finding, ...]
    unevaluated: tuple[Unevaluated, ...]
    backend_calls: int = 0
    cache_hits: int = 0
    tokens_used: int = 0
    prompt_versions: tuple[str, ...] = field(default_factory=tuple)


def _estimate_tokens(text: str) -> int:
    return len(text) // 4 + 1


class SemanticStage:
    def __init__(
        self,
        backend: SemanticBackendPort | None,
        *,
        system_prompt: str,  # Playbook Part B.1, loaded from data/prompts/_system.v<N>.md
        templates: Mapping[str, PromptTemplate],
        remediation: Mapping[str, str],
        options: SemanticOptions,
        cache: VerdictCachePort | None = None,
        egress: EgressLogPort | None = None,
    ) -> None:
        self._backend = backend
        self._system = system_prompt
        self._templates = templates
        self._remediation = remediation
        self._opts = options
        self._cache = cache
        self._egress = egress

    @property
    def backend_label(self) -> str:
        if self._backend is None:
            return "null"
        return f"{self._backend.name}:{self._backend.model_id}"

    def run(self, candidates: Iterable[Candidate]) -> SemanticResult:
        findings: list[Finding] = []
        unevaluated: list[Unevaluated] = []
        calls = hits = used = 0
        versions: set[str] = set()
        for cand in sorted(
            candidates, key=lambda c: (c.location.path, c.location.start_line, c.fingerprint)
        ):
            if self._backend is None:
                unevaluated.append(Unevaluated(cand, UnevaluatedReason.BACKEND_DISABLED))
                continue
            template = self._templates.get(cand.subcheck_id)
            if template is None:
                unevaluated.append(Unevaluated(cand, UnevaluatedReason.TEMPLATE_MISSING))
                continue
            versions.add(template.prompt_version)
            snippet, _ = redact(cand.snippet, self._opts.redact_patterns)
            user = template.render(cand, snippet)
            payload_sha = hashlib.sha256((self._system + "\n" + user).encode("utf-8")).hexdigest()
            key = hashlib.sha256(
                json.dumps([self._backend.model_id, template.prompt_version, payload_sha]).encode(
                    "utf-8"
                )
            ).hexdigest()

            cached = self._cache.get(key) if self._cache else None
            if cached is not None:
                hits += 1
                verdict = Verdict(**cached)
            else:
                cost = _estimate_tokens(self._system + user) + self._opts.max_tokens
                if used + cost > self._opts.token_budget:
                    unevaluated.append(Unevaluated(cand, UnevaluatedReason.BUDGET_EXHAUSTED))
                    continue
                request = SemanticRequest(
                    cand.subcheck_id,
                    template.prompt_version,
                    self._system,
                    user,
                    self._opts.max_tokens,
                    payload_sha,
                )
                calls += 1
                outcome = "ok"
                try:
                    response = self._backend.evaluate(request)
                    used += response.input_tokens + response.output_tokens or cost
                    verdict = parse_verdict(response.text)
                except BackendError as exc:
                    outcome = exc.kind
                    reason = (
                        UnevaluatedReason.TIMEOUT
                        if exc.kind == "timeout"
                        else UnevaluatedReason.BACKEND_ERROR
                    )
                    unevaluated.append(Unevaluated(cand, reason, str(exc)))
                    used += cost
                    continue
                except (ValueError, TypeError) as exc:
                    outcome = "parse_error"
                    unevaluated.append(Unevaluated(cand, UnevaluatedReason.PARSE_ERROR, str(exc)))
                    continue
                finally:
                    if self._egress is not None:
                        self._egress.record(
                            {
                                "backend": self._backend.name,
                                "model": self._backend.model_id,
                                "prompt_version": template.prompt_version,
                                "payload_sha256": payload_sha,
                                "outcome": outcome,
                            }
                        )
                if self._cache is not None:
                    self._cache.put(key, verdict.to_dict())

            if verdict.verdict == "insufficient_context":
                unevaluated.append(
                    Unevaluated(cand, UnevaluatedReason.INSUFFICIENT_CONTEXT, verdict.rationale)
                )
            elif verdict.verdict == "violation" and verdict.confidence >= self._opts.min_confidence:
                findings.append(self._finding(cand, verdict))
        return SemanticResult(
            tuple(findings), tuple(unevaluated), calls, hits, used, tuple(sorted(versions))
        )

    def _finding(self, cand: Candidate, verdict: Verdict) -> Finding:
        fix = self._remediation.get(cand.subcheck_id, "")
        if verdict.suggested_fix:
            fix = f"{fix} Suggested: {verdict.suggested_fix}".strip()
        return Finding(
            fingerprint=cand.fingerprint,
            rule_id=cand.rule_id,
            subcheck_id=cand.subcheck_id,
            severity=cand.severity,
            detection=Detection.SEMANTIC,
            origin=Origin.NOT_APPLICABLE,
            location=cand.location,
            component=cand.component,
            message=f"{cand.question} {verdict.rationale}".strip(),
            remediation=fix or None,
            source_tool=self.backend_label,
        )
