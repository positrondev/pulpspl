"""Alembic environment: CodePulse always hands over an open connection programmatically."""

from alembic import context

connection = context.config.attributes["connection"]
context.configure(
    connection=connection,
    target_metadata=None,
    render_as_batch=connection.dialect.name == "sqlite",
)
with context.begin_transaction():
    context.run_migrations()
