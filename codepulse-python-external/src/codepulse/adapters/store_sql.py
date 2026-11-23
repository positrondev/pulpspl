"""SQL findings store (spec 003). SQLAlchemy Core over SQLite or PostgreSQL.

Lifecycle decisions come from ``core.lifecycle``; this module only persists them, one
transaction per operation. ``check_history`` is insert-only here and in the database.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    Connection,
    Date,
    DateTime,
    Engine,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    event,
    func,
    select,
)
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from codepulse.core.delta import Baseline, BaselineFinding
from codepulse.core.errors import CodePulseError
from codepulse.core.governance import Decision
from codepulse.core.lifecycle import (
    ChangeKind,
    IssueState,
    IssueStatus,
    PlannedChange,
    TransitionError,
    Triage,
    plan_reconciliation,
    validate_triage,
)
from codepulse.core.model import Finding
from codepulse.core.registry import RuleRegistry
from codepulse.core.report import AnalysisReport, RunEnvelope

SYSTEM_PRINCIPAL = "codepulse"
md = MetaData()
# Mirrors migrations/versions/0001_initial.py (the migration is the source of truth).
run_record = Table(
    "run_record",
    md,
    Column("run_id", String(36), primary_key=True),
    Column("repository", String(255)),
    Column("target_ref", String(255)),
    Column("base_ref", String(255)),
    Column("mode", String(16)),
    Column("scope", JSON),
    Column("registry_version", String(96)),
    Column("config_hash", String(64)),
    Column("semantic_backend", String(128)),
    Column("prompt_versions", JSON),
    Column("files_eligible", Integer),
    Column("files_skipped", Integer),
    Column("findings_total", Integer),
    Column("candidates_unevaluated", Integer),
    Column("tokens_used", Integer),
    Column("duration_ms", BigInteger),
    Column("head_sha", String(64)),
    Column("created_at", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
)
rule_registry = Table(
    "rule_registry",
    md,
    Column("registry_version", String(96), primary_key=True),
    Column("subcheck_id", String(96), primary_key=True),
    Column("rule_id", String(32)),
    Column("rule_name", String(255)),
    Column("rule_type", String(32)),
    Column("severity_default", String(16)),
    Column("enabled", Boolean),
    Column("declarative_definition", JSON),
    Column("effective_from", DateTime(timezone=True)),
)
issue = Table(
    "issue",
    md,
    Column("issue_id", String(36), primary_key=True),
    Column("repository", String(255)),
    Column("fingerprint", String(24)),
    Column("rule_id", String(32)),
    Column("subcheck_id", String(96)),
    Column("path", Text),
    Column("detection", String(16)),
    Column("severity", String(16)),
    Column("status", String(16)),
    Column("rejection_reason", String(32)),
    Column("waiver_justification", Text),
    Column("waiver_expires_at", Date),
    Column("first_seen_run_id", String(36), ForeignKey("run_record.run_id")),
    Column("last_seen_run_id", String(36), ForeignKey("run_record.run_id")),
    Column("owner", String(128)),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)
finding_occurrence = Table(
    "finding_occurrence",
    md,
    Column("occurrence_id", String(36), primary_key=True),
    Column("run_id", String(36), ForeignKey("run_record.run_id")),
    Column("issue_id", String(36), ForeignKey("issue.issue_id")),
    Column("fingerprint", String(24)),
    Column("file_path", Text),
    Column("start_line", Integer),
    Column("end_line", Integer),
    Column("element_id", String(256)),
    Column("component", String(32)),
    Column("severity", String(16)),
    Column("detection", String(16)),
    Column("source_tool", String(128)),
    Column("origin", String(16)),
    Column("description", Text),
    Column("remediation", Text),
    Column("suppressed", Boolean),
)
check_history = Table(
    "check_history",
    md,
    Column("history_id", String(36), primary_key=True),
    Column("issue_id", String(36), ForeignKey("issue.issue_id")),
    Column("run_id", String(36), ForeignKey("run_record.run_id")),
    Column("previous_status", String(16)),
    Column("new_status", String(16)),
    Column("changed_by", String(128)),
    Column("source", String(32)),
    Column("reason_code", String(32)),
    Column("evidence_ref", Text),
    Column("note", Text),
    Column("changed_at", DateTime(timezone=True)),
)


class StoreError(CodePulseError):
    """Store unavailable or not migrated. Maps to exit code 2."""


def _alembic(conn: Connection) -> AlembicConfig:
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(files("codepulse").joinpath("adapters/migrations")))
    cfg.attributes["connection"] = conn
    return cfg


def make_engine(url: str) -> Engine:
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite" and parsed.database not in (None, "", ":memory:"):
        Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
    # A CLI run is short-lived: no pool to size or leak (and E09 asks for an explicit choice).
    engine = create_engine(url, poolclass=NullPool)
    if parsed.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn: Any, _record: Any) -> None:
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return engine


def upgrade(engine: Engine) -> str:
    with engine.begin() as conn:
        cfg = _alembic(conn)
        command.upgrade(cfg, "head")
        return str(ScriptDirectory.from_config(cfg).get_current_head())


def _require_current(conn: Connection) -> None:
    head = ScriptDirectory.from_config(_alembic(conn)).get_current_head()
    current = MigrationContext.configure(conn).get_current_revision()
    if current != head:
        raise StoreError(
            f"findings store is at revision {current or 'none'}, expected {head}; "
            "run `codepulse db upgrade`"
        )


@dataclass(frozen=True, slots=True)
class RecordSummary:
    created: int
    resolved: int
    reopened: int
    waivers_expired: int
    occurrences: int


def _now() -> datetime:
    return datetime.now(UTC)


class SqlFindingStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # -- writes -------------------------------------------------------------------------

    def record_run(
        self,
        report: AnalysisReport,
        envelope: RunEnvelope,
        registry: RuleRegistry,
        today: date,
    ) -> RecordSummary:
        repo = report.target.repository
        present = [*report.findings, *(s.finding for s in report.suppressed)]
        suppressed = {s.finding.fingerprint for s in report.suppressed}
        created_at = datetime.fromisoformat(envelope.started_at)
        with self._engine.begin() as conn:
            _require_current(conn)
            conn.execute(
                run_record.insert().values(
                    run_id=envelope.run_id,
                    repository=repo,
                    target_ref=report.target.head or str(report.target.mode),
                    base_ref=report.target.base,
                    mode=str(report.target.mode),
                    scope={"files_analyzed": list(report.files_analyzed)},
                    registry_version=report.registry_version,
                    config_hash=report.config_hash,
                    semantic_backend=report.semantic_backend,
                    prompt_versions=list(report.prompt_versions),
                    files_eligible=len(report.files_analyzed),
                    files_skipped=len(report.skipped),
                    findings_total=len(report.findings),
                    candidates_unevaluated=len(report.needs_review),
                    tokens_used=envelope.semantic_tokens,
                    duration_ms=envelope.duration_ms,
                    head_sha=envelope.head_sha,
                    created_at=created_at,
                    completed_at=datetime.fromisoformat(envelope.completed_at),
                )
            )
            self._snapshot_registry(conn, registry, created_at)
            rows = conn.execute(select(issue).where(issue.c.repository == repo)).mappings().all()
            ids = {r["fingerprint"]: r["issue_id"] for r in rows}
            existing = {
                r["fingerprint"]: IssueState(
                    r["fingerprint"],
                    r["subcheck_id"],
                    r["path"],
                    IssueStatus(r["status"]),
                    r["waiver_expires_at"],
                )
                for r in rows
            }
            plan = plan_reconciliation(existing, present, report.files_analyzed, today)
            counts = dict.fromkeys(ChangeKind, 0)
            now = _now()
            for change in plan:
                counts[change.kind] += 1
                ids.setdefault(change.fingerprint, str(uuid.uuid4()))
                self._apply(conn, repo, ids[change.fingerprint], change, envelope.run_id, now)
            by_fp = {f.fingerprint: f for f in present}
            for fp in sorted(by_fp):
                self._occurrence(conn, envelope.run_id, ids[fp], by_fp[fp], fp in suppressed)
        return RecordSummary(
            counts[ChangeKind.CREATE],
            counts[ChangeKind.RESOLVE],
            counts[ChangeKind.REOPEN],
            counts[ChangeKind.EXPIRE_WAIVER],
            len(by_fp),
        )

    def _snapshot_registry(self, conn: Connection, registry: RuleRegistry, at: datetime) -> None:
        known = conn.execute(
            select(func.count())
            .select_from(rule_registry)
            .where(rule_registry.c.registry_version == registry.version)
        ).scalar_one()
        if known:
            return
        # Snapshot custom declarative rules alongside enabled legacy AST checks.
        for sid in [*(sc.id for sc in registry.active), *(r.id for r in registry.external_rules)]:
            m = registry.meta(sid)
            conn.execute(
                rule_registry.insert().values(
                    registry_version=registry.version,
                    subcheck_id=m.id,
                    rule_id=m.rule_id,
                    rule_name=m.rule_name,
                    rule_type=str(m.detection),
                    severity_default=str(m.severity),
                    enabled=m.enabled,
                    declarative_definition={"message": m.message, "options": dict(m.options)},
                    effective_from=at,
                )
            )

    def _apply(
        self,
        conn: Connection,
        repo: str,
        issue_id: str,
        change: PlannedChange,
        run_id: str,
        now: datetime,
    ) -> None:
        f = change.finding
        if change.kind is ChangeKind.CREATE:
            if f is None or change.new is None:
                raise StoreError(f"invalid plan: CREATE for {change.fingerprint} lacks a finding")
            conn.execute(
                issue.insert().values(
                    issue_id=issue_id,
                    repository=repo,
                    fingerprint=change.fingerprint,
                    rule_id=f.rule_id,
                    subcheck_id=f.subcheck_id,
                    path=f.location.path,
                    detection=str(f.detection),
                    severity=str(f.severity),
                    status=str(change.new),
                    first_seen_run_id=run_id,
                    last_seen_run_id=run_id,
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            values: dict[str, Any] = {"updated_at": now}
            if f is not None:
                values.update(last_seen_run_id=run_id, severity=str(f.severity))
            if change.new is not None:
                values["status"] = str(change.new)
            conn.execute(issue.update().where(issue.c.issue_id == issue_id).values(**values))
        if change.new is not None:
            self._history(
                conn,
                issue_id,
                run_id,
                change.previous,
                change.new,
                SYSTEM_PRINCIPAL,
                "reconciler",
                note=change.note,
                at=now,
            )

    def _occurrence(
        self, conn: Connection, run_id: str, issue_id: str, f: Finding, suppressed: bool
    ) -> None:
        conn.execute(
            finding_occurrence.insert().values(
                occurrence_id=str(uuid.uuid4()),
                run_id=run_id,
                issue_id=issue_id,
                fingerprint=f.fingerprint,
                file_path=f.location.path,
                start_line=f.location.start_line,
                end_line=f.location.end_line,
                element_id=f.location.scope,
                component=str(f.component),
                severity=str(f.severity),
                detection=str(f.detection),
                source_tool=f.source_tool,
                origin=str(f.origin),
                description=f.message,
                remediation=f.remediation,
                suppressed=suppressed,
            )
        )

    def _history(
        self,
        conn: Connection,
        issue_id: str,
        run_id: str | None,
        previous: IssueStatus | None,
        new: IssueStatus,
        by: str,
        source: str,
        *,
        reason: str | None = None,
        evidence: str | None = None,
        note: str = "",
        at: datetime,
    ) -> None:
        conn.execute(
            check_history.insert().values(
                history_id=str(uuid.uuid4()),
                issue_id=issue_id,
                run_id=run_id,
                previous_status=None if previous is None else str(previous),
                new_status=str(new),
                changed_by=by,
                source=source,
                reason_code=reason,
                evidence_ref=evidence,
                note=note or None,
                changed_at=at,
            )
        )

    def triage(self, repository: str, t: Triage, today: date) -> tuple[str, IssueStatus]:
        """Apply a reviewer decision. Accepts a unique fingerprint prefix (>= 8 chars)."""
        if len(t.fingerprint) < 8:
            raise TransitionError("fingerprint prefix must be at least 8 characters")
        with self._engine.begin() as conn:
            _require_current(conn)
            rows = (
                conn.execute(
                    select(issue).where(
                        issue.c.repository == repository,
                        issue.c.fingerprint.startswith(t.fingerprint),
                    )
                )
                .mappings()
                .all()
            )
            if not rows:
                raise TransitionError(f"no issue {t.fingerprint!r} in {repository}")
            if len(rows) > 1:
                raise TransitionError(
                    f"fingerprint prefix {t.fingerprint!r} is ambiguous ({len(rows)} issues)"
                )
            row = rows[0]
            current = IssueStatus(row["status"])
            validate_triage(current, t, today)
            values: dict[str, Any] = {"status": str(t.status), "updated_at": _now()}
            if t.status is IssueStatus.REJECTED:
                values["rejection_reason"] = str(t.reason)
            if t.status is IssueStatus.WAIVED:
                values.update(waiver_justification=t.justification, waiver_expires_at=t.until)
            conn.execute(issue.update().where(issue.c.issue_id == row["issue_id"]).values(**values))
            self._history(
                conn,
                row["issue_id"],
                None,
                current,
                t.status,
                t.by,
                "cli",
                reason=None if t.reason is None else str(t.reason),
                evidence=t.evidence,
                note=t.justification or "",
                at=_now(),
            )
            return str(row["fingerprint"]), current

    # -- reads --------------------------------------------------------------------------

    def issues(self, repository: str, status: IssueStatus | None = None) -> list[dict[str, Any]]:
        with self._engine.connect() as conn:
            _require_current(conn)
            q = select(issue).where(issue.c.repository == repository)
            if status is not None:
                q = q.where(issue.c.status == str(status))
            rows = conn.execute(
                q.order_by(issue.c.severity, issue.c.path, issue.c.fingerprint)
            ).mappings()
            return [dict(r) for r in rows]

    def repositories(self) -> list[str]:
        with self._engine.connect() as conn:
            _require_current(conn)
            return list(
                conn.execute(
                    select(run_record.c.repository).distinct().order_by(run_record.c.repository)
                ).scalars()
            )

    def issue_details(self, repository: str) -> list[dict[str, Any]]:
        """Every issue with its most recent occurrence (line, message, fix, component):
        what a dashboard row or a tracker ticket needs (spec 009 FR-908/909)."""
        occ = finding_occurrence
        with self._engine.connect() as conn:
            _require_current(conn)
            rows = conn.execute(
                select(
                    issue,
                    occ.c.start_line,
                    occ.c.component,
                    occ.c.origin,
                    occ.c.description,
                    occ.c.remediation,
                    occ.c.suppressed,
                    run_record.c.created_at.label("last_seen_at"),
                )
                .select_from(
                    issue.join(
                        occ,
                        (occ.c.issue_id == issue.c.issue_id)
                        & (occ.c.run_id == issue.c.last_seen_run_id),
                    ).join(run_record, run_record.c.run_id == issue.c.last_seen_run_id)
                )
                .where(issue.c.repository == repository)
                .order_by(issue.c.path, occ.c.start_line, issue.c.fingerprint)
            ).mappings()
            return [dict(r) for r in rows]

    def history(self, issue_ids: Iterable[str]) -> list[dict[str, Any]]:
        ids = list(issue_ids)
        with self._engine.connect() as conn:
            q = (
                select(check_history)
                .where(check_history.c.issue_id.in_(ids))
                .order_by(check_history.c.changed_at)
            )
            return [dict(r) for r in conn.execute(q).mappings()]

    def recent_runs(self, repository: str, limit: int) -> list[dict[str, Any]]:
        with self._engine.connect() as conn:
            _require_current(conn)
            runs = (
                conn.execute(
                    select(run_record)
                    .where(run_record.c.repository == repository)
                    .order_by(run_record.c.created_at.desc(), run_record.c.completed_at.desc())
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            out = []
            for r in reversed(runs):
                sev = conn.execute(
                    select(finding_occurrence.c.severity, func.count())
                    .where(
                        finding_occurrence.c.run_id == r["run_id"],
                        finding_occurrence.c.suppressed.is_(False),
                    )
                    .group_by(finding_occurrence.c.severity)
                ).all()
                comp = conn.execute(
                    select(finding_occurrence.c.component, func.count())
                    .where(
                        finding_occurrence.c.run_id == r["run_id"],
                        finding_occurrence.c.suppressed.is_(False),
                    )
                    .group_by(finding_occurrence.c.component)
                ).all()
                out.append({**dict(r), "by_severity": dict(sev), "by_component": dict(comp)})
            return out

    def previous_baseline(self, repository: str, target_ref: str) -> Baseline | None:
        """The latest stored run on the same ref, as a delta baseline (spec 006 FR-601).
        Labelled by commit, not run id, so the report stays content-derived."""
        with self._engine.connect() as conn:
            _require_current(conn)
            run = (
                conn.execute(
                    select(run_record.c.run_id, run_record.c.head_sha)
                    .where(
                        run_record.c.repository == repository,
                        run_record.c.target_ref == target_ref,
                    )
                    .order_by(run_record.c.created_at.desc(), run_record.c.completed_at.desc())
                    .limit(1)
                )
                .mappings()
                .first()
            )
            if run is None:
                return None
            rows = conn.execute(
                select(
                    finding_occurrence.c.fingerprint,
                    issue.c.subcheck_id,
                    finding_occurrence.c.file_path,
                    finding_occurrence.c.start_line,
                    finding_occurrence.c.severity,
                )
                .select_from(
                    finding_occurrence.join(
                        issue, finding_occurrence.c.issue_id == issue.c.issue_id
                    )
                )
                .where(
                    finding_occurrence.c.run_id == run["run_id"],
                    finding_occurrence.c.suppressed.is_(False),
                )
                .order_by(finding_occurrence.c.fingerprint)
            ).all()
        label = f"store:{(run['head_sha'] or target_ref)[:12]}"
        return Baseline(label, tuple(BaselineFinding(*r) for r in rows))

    def decisions(self, repository: str | None = None) -> list[Decision]:
        """Reviewer decisions only (source ``cli``): calibration must not count the
        reconciler's automatic moves, or confirmed-on-raise would inflate every rate."""
        decided = [str(s) for s in IssueStatus if s is not IssueStatus.OPEN]
        joined = check_history.join(issue, check_history.c.issue_id == issue.c.issue_id)
        q = (
            select(issue.c.subcheck_id, check_history.c.new_status, check_history.c.changed_at)
            .select_from(joined)
            .where(check_history.c.source == "cli", check_history.c.new_status.in_(decided))
        )
        if repository is not None:
            q = q.where(issue.c.repository == repository)
        with self._engine.connect() as conn:
            _require_current(conn)
            return [
                Decision(sub, IssueStatus(status), at)
                for sub, status, at in conn.execute(q.order_by(check_history.c.changed_at))
            ]
