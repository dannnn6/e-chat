"""Schema v1. All timestamps are UTC epoch milliseconds; IDs are opaque strings."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
import time
from sqlalchemy import (create_engine, event, MetaData, Table, Column, String, Text,
    BigInteger, Integer, Boolean, LargeBinary, ForeignKey, UniqueConstraint, Index,
    select, insert, update, func)

meta = MetaData()
versions = Table('schema_versions', meta, Column('version', Integer, primary_key=True))
users = Table('users', meta, Column('id', String(44), primary_key=True),
    Column('name', String(80), nullable=False), Column('public_key', LargeBinary, nullable=False),
    Column('disabled', Boolean, nullable=False, default=False), Column('created_at', BigInteger, nullable=False))
clocks = Table('user_clocks', meta, Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('revision', BigInteger, nullable=False, default=0))
devices = Table('devices', meta, Column('id', String(64), primary_key=True),
    Column('user_id', ForeignKey('users.id'), nullable=False, index=True),
    Column('public_key', LargeBinary, nullable=False), Column('name', String(80), nullable=False),
    Column('revoked', Boolean, nullable=False, default=False), Column('created_at', BigInteger, nullable=False))
sessions = Table('sessions', meta, Column('token_hash', String(64), primary_key=True),
    Column('device_id', ForeignKey('devices.id'), nullable=False, index=True),
    Column('expires_at', BigInteger, nullable=False, index=True))
challenges = Table('challenges', meta, Column('id', String(32), primary_key=True),
    Column('payload', Text, nullable=False), Column('transcript', Text, nullable=False),
    Column('expires_at', BigInteger, nullable=False, index=True))
conversations = Table('conversations', meta, Column('id', String(32), primary_key=True),
    Column('kind', String(12), nullable=False), Column('title', String(120), nullable=False),
    Column('owner_id', ForeignKey('users.id'), nullable=False),
    Column('creator_id', ForeignKey('users.id'), nullable=False),
    Column('direct_key', String(100), unique=True), Column('client_id', String(64)),
    Column('last_seq', BigInteger, nullable=False, default=0), Column('updated_at', BigInteger, nullable=False),
    UniqueConstraint('creator_id', 'client_id', name='uq_conversation_request'))
members = Table('members', meta,
    Column('conversation_id', ForeignKey('conversations.id'), primary_key=True),
    Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('role', String(12), nullable=False), Column('read_seq', BigInteger, nullable=False, default=0),
    Column('muted', Boolean, nullable=False, default=False))
Index('ix_members_user', members.c.user_id, members.c.conversation_id)
messages = Table('messages', meta, Column('id', String(32), primary_key=True),
    Column('conversation_id', ForeignKey('conversations.id'), nullable=False),
    Column('seq', BigInteger, nullable=False), Column('sender_id', ForeignKey('users.id'), nullable=False),
    Column('client_id', String(64), nullable=False), Column('body', LargeBinary, nullable=False),
    Column('created_at', BigInteger, nullable=False), Column('version', Integer, nullable=False, default=1),
    Column('edited', Boolean, nullable=False, default=False), Column('deleted', Boolean, nullable=False, default=False),
    Column('reply_to', String(32)),
    UniqueConstraint('conversation_id', 'seq', name='uq_message_sequence'),
    UniqueConstraint('sender_id', 'client_id', name='uq_message_request'))
Index('ix_messages_history', messages.c.conversation_id, messages.c.seq)
events = Table('events', meta, Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('revision', BigInteger, primary_key=True), Column('conversation_id', String(32), nullable=False),
    Column('message_id', String(32)), Column('created_at', BigInteger, nullable=False))
blocks = Table('blocks', meta, Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('peer_id', ForeignKey('users.id'), primary_key=True))
invites = Table('invites', meta, Column('token_hash', String(64), primary_key=True),
    Column('conversation_id', ForeignKey('conversations.id'), nullable=False, index=True),
    Column('expires_at', BigInteger, nullable=False), Column('uses_left', Integer, nullable=False))
uploads = Table('uploads', meta, Column('id', String(32), primary_key=True),
    Column('owner_id', ForeignKey('users.id'), nullable=False, index=True),
    Column('conversation_id', ForeignKey('conversations.id'), nullable=False),
    Column('client_id', String(64), nullable=False), Column('name', String(160), nullable=False),
    Column('mime', String(120), nullable=False), Column('total', BigInteger, nullable=False),
    Column('offset', BigInteger, nullable=False, default=0), Column('sha256', String(64), nullable=False),
    Column('ready', Boolean, nullable=False, default=False), Column('message_id', ForeignKey('messages.id')),
    Column('created_at', BigInteger, nullable=False),
    UniqueConstraint('owner_id', 'client_id', name='uq_upload_request'))
Index('ix_uploads_message', uploads.c.message_id)


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class Database:
    def __init__(self, url: str):
        kwargs = {'pool_pre_ping': True}
        self.sqlite = url.startswith('sqlite:')
        if self.sqlite:
            kwargs['connect_args'] = {'check_same_thread': False, 'timeout': 30}
            if url.endswith(':memory:'):
                from sqlalchemy.pool import StaticPool
                kwargs['poolclass'] = StaticPool
        else:
            kwargs.update(pool_size=8, max_overflow=8, pool_timeout=15)
        self.engine = create_engine(url, **kwargs)
        if self.sqlite:
            @event.listens_for(self.engine, 'connect')
            def sqlite_setup(connection, _):
                cur = connection.cursor()
                cur.execute('PRAGMA foreign_keys=ON')
                cur.execute('PRAGMA journal_mode=WAL')
                cur.execute('PRAGMA busy_timeout=30000')
                cur.close()

    @contextmanager
    def tx(self, *, write=False, snapshot=False):
        with self.engine.connect() as c:
            if snapshot and not self.sqlite:
                c = c.execution_options(isolation_level='REPEATABLE READ')
            if write and self.sqlite:
                c.exec_driver_sql('BEGIN IMMEDIATE')
            else:
                c.begin()
            try:
                yield c
                c.commit()
            except BaseException:
                c.rollback()
                raise

    def migrate(self):
        with self.tx(write=True) as c:
            if not self.sqlite:
                c.exec_driver_sql('SELECT pg_advisory_xact_lock(735920061)')
            meta.create_all(c)
            existing = c.execute(select(versions.c.version)).scalars().all()
            if not existing:
                c.execute(insert(versions).values(version=1))
            elif existing != [1]:
                raise RuntimeError('Unsupported schema version; restore or migrate explicitly')

    def check(self):
        with self.tx() as c:
            if c.execute(select(versions.c.version)).scalars().all() != [1]:
                raise RuntimeError('Run python -m echat migrate before serving requests')

    def emit(self, c, user_ids, conversation_id: str, message_id: str | None = None):
        # Every writer locks user clocks in the same order. Unlike a global SQL
        # sequence, this cursor cannot publish revision N+1 before N commits.
        for uid in sorted(set(user_ids)):
            rev = c.execute(select(clocks.c.revision).where(clocks.c.user_id == uid)
                            .with_for_update()).scalar_one() + 1
            c.execute(update(clocks).where(clocks.c.user_id == uid).values(revision=rev))
            c.execute(insert(events).values(user_id=uid, revision=rev,
                conversation_id=conversation_id, message_id=message_id, created_at=now_ms()))
            if not self.sqlite:
                c.execute(select(func.pg_notify('echat_changes', uid)))