"""Create the MCP Sentinel system-of-record schema.

Revision ID: 0001
Revises: none
"""

from alembic import op

from mcp_sentinel_api.database import Base
from mcp_sentinel_api import models  # noqa: F401


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all v0.1 tables and indexes from the reviewed SQLAlchemy metadata."""
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    """Drop the v0.1 schema. Production operators must back up before downgrade."""
    Base.metadata.drop_all(bind=op.get_bind())
