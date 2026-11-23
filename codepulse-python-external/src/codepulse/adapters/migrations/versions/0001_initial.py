"""Initial findings store schema (APDD v4.1 §8). Frozen: never edit, add a new revision.

Revision ID: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_record",
        sa.Column("run_id", sa.String(36), primary_key=True),
        sa.Column("repository", sa.String(255), nullable=False),
        sa.Column("target_ref", sa.String(255), nullable=False),
        sa.Column("base_ref", sa.String(255)),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("scope", sa.JSON, nullable=False),
        sa.Column("registry_version", sa.String(96), nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("semantic_backend", sa.String(128)),
        sa.Column("prompt_versions", sa.JSON),
        sa.Column("files_eligible", sa.Integer, nullable=False),
        sa.Column("files_skipped", sa.Integer, nullable=False),
        sa.Column("findings_total", sa.Integer, nullable=False),
        sa.Column("candidates_unevaluated", sa.Integer, nullable=False),
        sa.Column("tokens_used", sa.Integer),
        sa.Column("duration_ms", sa.BigInteger, nullable=False),
        sa.Column("head_sha", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_run_repo_ref_created", "run_record", ["repository", "target_ref", "created_at"]
    )
    op.create_table(
        "rule_registry",
        sa.Column("registry_version", sa.String(96), primary_key=True),
        sa.Column("subcheck_id", sa.String(96), primary_key=True),
        sa.Column("rule_id", sa.String(32), nullable=False),
        sa.Column("rule_name", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(32), nullable=False),
        sa.Column("severity_default", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("declarative_definition", sa.JSON, nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "issue",
        sa.Column("issue_id", sa.String(36), primary_key=True),
        sa.Column("repository", sa.String(255), nullable=False),
        sa.Column("fingerprint", sa.String(24), nullable=False),
        sa.Column("rule_id", sa.String(32), nullable=False),
        sa.Column("subcheck_id", sa.String(96), nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("detection", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("rejection_reason", sa.String(32)),
        sa.Column("waiver_justification", sa.Text),
        sa.Column("waiver_expires_at", sa.Date),
        sa.Column(
            "first_seen_run_id", sa.String(36), sa.ForeignKey("run_record.run_id"), nullable=False
        ),
        sa.Column(
            "last_seen_run_id", sa.String(36), sa.ForeignKey("run_record.run_id"), nullable=False
        ),
        sa.Column("owner", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("repository", "fingerprint", name="uq_issue_repo_fingerprint"),
        sa.CheckConstraint(
            "status <> 'waived' OR waiver_justification IS NOT NULL", name="ck_waiver_justified"
        ),
        sa.CheckConstraint(
            "status <> 'rejected' OR rejection_reason IS NOT NULL", name="ck_rejection_reason"
        ),
    )
    op.create_index("ix_issue_repo_status", "issue", ["repository", "status"])
    op.create_table(
        "finding_occurrence",
        sa.Column("occurrence_id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("run_record.run_id"), nullable=False),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issue.issue_id"), nullable=False),
        sa.Column("fingerprint", sa.String(24), nullable=False),
        sa.Column("file_path", sa.Text, nullable=False),
        sa.Column("start_line", sa.Integer, nullable=False),
        sa.Column("end_line", sa.Integer, nullable=False),
        sa.Column("element_id", sa.String(256)),
        sa.Column("component", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("detection", sa.String(16), nullable=False),
        sa.Column("source_tool", sa.String(128)),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("remediation", sa.Text),
        sa.Column("suppressed", sa.Boolean, nullable=False),
        sa.UniqueConstraint("run_id", "fingerprint", name="uq_occurrence_run_fingerprint"),
    )
    op.create_table(
        "check_history",
        sa.Column("history_id", sa.String(36), primary_key=True),
        sa.Column("issue_id", sa.String(36), sa.ForeignKey("issue.issue_id"), nullable=False),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("run_record.run_id")),
        sa.Column("previous_status", sa.String(16)),
        sa.Column("new_status", sa.String(16), nullable=False),
        sa.Column("changed_by", sa.String(128), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(32)),
        sa.Column("evidence_ref", sa.Text),
        sa.Column("note", sa.Text),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_history_issue", "check_history", ["issue_id", "changed_at"])

    # Append-only audit trail, enforced by the database itself (APDD §8.5).
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER check_history_no_{action.lower()} "
                f"BEFORE {action} ON check_history "
                "BEGIN SELECT RAISE(ABORT, 'check_history is append-only'); END"
            )
    elif dialect == "postgresql":
        op.execute(
            "CREATE FUNCTION check_history_append_only() RETURNS trigger LANGUAGE plpgsql AS "
            "$$ BEGIN RAISE EXCEPTION 'check_history is append-only'; END $$"
        )
        op.execute(
            "CREATE TRIGGER check_history_append_only BEFORE UPDATE OR DELETE ON check_history "
            "FOR EACH ROW EXECUTE FUNCTION check_history_append_only()"
        )


def downgrade() -> None:
    raise NotImplementedError(
        "the findings store is append-only evidence; restore from backup instead"
    )
