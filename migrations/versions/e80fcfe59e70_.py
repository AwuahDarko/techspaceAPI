"""empty message

Revision ID: e80fcfe59e70
Revises: 7a680b846df6
Create Date: 2020-04-15 12:25:00.165438

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e80fcfe59e70'
down_revision = '7a680b846df6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('interests',
    sa.Column('interest_id', sa.Integer(), nullable=False),
    sa.Column('interest_name', sa.String(length=45), nullable=True),
    sa.PrimaryKeyConstraint('interest_id'),
    sa.UniqueConstraint('interest_name')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('interests')
    # ### end Alembic commands ###