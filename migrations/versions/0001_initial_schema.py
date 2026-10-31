"""initial schema

Reviewed by hand: column types are spelled out (no imports from app code) so this migration stays valid
even if app/db_types.py is refactored later. PostgreSQL is the production target.

Revision ID: 0001
Revises: 
Create Date: 2026-10-24 23:21:29.783525

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('resources',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('content', sa.Text(), nullable=True),
    sa.Column('is_honeypot', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_resources')),
    sa.UniqueConstraint('name', name=op.f('uq_resources_name'))
    )
    op.create_table('users',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=False),
    sa.Column('employee_id', sa.String(length=20), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('risk_score', sa.Integer(), server_default='0', nullable=False),
    sa.Column('risk_updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('Admin', 'IT', 'HR', 'Finance', 'Marketing', 'Operations')", name=op.f('ck_users_role_valid')),
    sa.CheckConstraint('risk_score BETWEEN 0 AND 100', name=op.f('ck_users_risk_score_range')),
    sa.CheckConstraint('username = lower(username)', name=op.f('ck_users_username_lowercase')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('employee_id', name=op.f('uq_users_employee_id')),
    sa.UniqueConstraint('username', name=op.f('uq_users_username'))
    )
    op.create_table('incidents',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('summary', sa.Text(), server_default='', nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('status', sa.String(length=15), server_default='open', nullable=False),
    sa.Column('rule_id', sa.String(length=20), nullable=False),
    sa.Column('mitre_tactic', sa.String(length=60), nullable=True),
    sa.Column('mitre_technique', sa.String(length=12), nullable=True),
    sa.Column('user_id', sa.BigInteger(), nullable=True),
    sa.Column('subject', sa.String(length=100), nullable=False),
    sa.Column('source_ip', postgresql.INET(), nullable=True),
    sa.Column('dedupe_key', sa.String(length=200), nullable=False),
    sa.Column('risk_score', sa.Integer(), server_default='0', nullable=False),
    sa.Column('resolved_by_id', sa.BigInteger(), nullable=True),
    sa.Column('opened_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name=op.f('ck_incidents_severity_valid')),
    sa.CheckConstraint("status IN ('open', 'investigating', 'resolved')", name=op.f('ck_incidents_status_valid')),
    sa.ForeignKeyConstraint(['resolved_by_id'], ['users.id'], name=op.f('fk_incidents_resolved_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_incidents_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents'))
    )
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.create_index('ix_incidents_status_opened', ['status', 'opened_at'], unique=False)
        batch_op.create_index('uq_incidents_open_dedupe', ['dedupe_key'], unique=True, postgresql_where=sa.text("status IN ('open', 'investigating')"))

    op.create_table('resource_permissions',
    sa.Column('resource_id', sa.BigInteger(), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.CheckConstraint("role IN ('Admin', 'IT', 'HR', 'Finance', 'Marketing', 'Operations')", name=op.f('ck_resource_permissions_role_valid')),
    sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], name=op.f('fk_resource_permissions_resource_id_resources'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('resource_id', 'role', name=op.f('pk_resource_permissions'))
    )
    op.create_table('security_events',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('event_type', sa.String(length=30), nullable=False),
    sa.Column('outcome', sa.String(length=10), nullable=False),
    sa.Column('severity', sa.String(length=10), server_default='info', nullable=False),
    sa.Column('user_id', sa.BigInteger(), nullable=True),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('resource_id', sa.BigInteger(), nullable=True),
    sa.Column('resource_name', sa.String(length=100), nullable=True),
    sa.Column('source_ip', postgresql.INET(), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.CheckConstraint("event_type IN ('login_success', 'login_failed', 'login_blocked', 'logout', 'access_granted', 'access_denied', 'honeypot_access')", name=op.f('ck_security_events_event_type_valid')),
    sa.CheckConstraint("outcome IN ('success', 'failure', 'blocked')", name=op.f('ck_security_events_outcome_valid')),
    sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name=op.f('ck_security_events_severity_valid')),
    sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], name=op.f('fk_security_events_resource_id_resources'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_security_events_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_events'))
    )
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.create_index('ix_security_events_ip_time', ['source_ip', 'occurred_at'], unique=False)
        batch_op.create_index('ix_security_events_occurred_at', ['occurred_at'], unique=False)
        batch_op.create_index('ix_security_events_type_time', ['event_type', 'occurred_at'], unique=False)
        batch_op.create_index('ix_security_events_user_time', ['user_id', 'occurred_at'], unique=False)

    op.create_table('incident_activity',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('incident_id', sa.BigInteger(), nullable=False),
    sa.Column('actor_id', sa.BigInteger(), nullable=True),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("kind IN ('opened', 'evidence_added', 'status_changed', 'note')", name=op.f('ck_incident_activity_kind_valid')),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_incident_activity_actor_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_incident_activity_incident_id_incidents'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incident_activity'))
    )
    with op.batch_alter_table('incident_activity', schema=None) as batch_op:
        batch_op.create_index('ix_incident_activity_incident_time', ['incident_id', 'created_at'], unique=False)

    op.create_table('incident_events',
    sa.Column('incident_id', sa.BigInteger(), nullable=False),
    sa.Column('event_id', sa.BigInteger(), nullable=False),
    sa.Column('linked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['event_id'], ['security_events.id'], name=op.f('fk_incident_events_event_id_security_events'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_incident_events_incident_id_incidents'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('incident_id', 'event_id', name=op.f('pk_incident_events'))
    )


def downgrade():
    op.drop_table('incident_events')
    with op.batch_alter_table('incident_activity', schema=None) as batch_op:
        batch_op.drop_index('ix_incident_activity_incident_time')

    op.drop_table('incident_activity')
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.drop_index('ix_security_events_user_time')
        batch_op.drop_index('ix_security_events_type_time')
        batch_op.drop_index('ix_security_events_occurred_at')
        batch_op.drop_index('ix_security_events_ip_time')

    op.drop_table('security_events')
    op.drop_table('resource_permissions')
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index('uq_incidents_open_dedupe', postgresql_where=sa.text("status IN ('open', 'investigating')"))
        batch_op.drop_index('ix_incidents_status_opened')

    op.drop_table('incidents')
    op.drop_table('users')
    op.drop_table('resources')
