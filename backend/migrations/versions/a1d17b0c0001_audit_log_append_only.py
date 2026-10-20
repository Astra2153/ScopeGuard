"""audit log is append only

Revision ID: a1d17b0c0001
Revises: 9ea9a28134ae
"""
from typing import Sequence, Union

from alembic import op

revision: str = "a1d17b0c0001"
down_revision: Union[str, None] = "9ea9a28134ae"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION audit_log_block_change() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_block_change()"
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_change()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_block_change()")
