"""Add assigned_poc to Task

Revision ID: c4ac2ad86007
Revises: a6fc5c011a03
Create Date: 2025-01-12 18:47:34.969360

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4ac2ad86007'
down_revision = 'a6fc5c011a03'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('task', schema=None) as batch_op:
        batch_op.add_column(sa.Column('assigned_poc', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_task_assigned_poc',  # Name of the foreign key
            'user',                 # Referenced table
            ['assigned_poc'],       # Local columns
            ['id']                  # Referenced columns
        )



def downgrade():
    with op.batch_alter_table('task', schema=None) as batch_op:
        batch_op.drop_constraint('fk_task_assigned_poc', type_='foreignkey')
        batch_op.drop_column('assigned_poc')
