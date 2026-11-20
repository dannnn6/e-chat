from __future__ import annotations
import hashlib
import os
import re
import uuid
from sqlalchemy import select, insert, update, func
from .db import uploads, messages, users, now_ms
from .auth import Fault, text, integer

class Media:
    """Sequential resumable uploads. SQL offset is authoritative after a crash."""
    def __init__(self, service):
        self.service, self.db = service, service.db
        self.root = service.settings.data_dir / 'blobs'
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, uid):
        if not re.fullmatch(r'[0-9a-f]{32}', uid):
            raise Fault(400, 'Invalid upload id')
        return self.root / uid[:2] / uid

    def start(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        client = text(data.get('clientId'), 'clientId', 64)
        name = text(data.get('name'), 'name', 160).replace('/', '_').replace('\\', '_')
        if any(ord(ch) < 32 for ch in name):
            raise Fault(400, 'Invalid filename')
        total = integer(data.get('total'), 'total', 1, self.service.settings.max_upload)
        digest = text(data.get('sha256'), 'sha256', 64).lower()
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise Fault(400, 'SHA-256 required')
        mime = text(data.get('mime', 'application/octet-stream'), 'mime', 120)
        if not re.fullmatch(r'[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+', mime):
            mime = 'application/octet-stream'
        with self.db.tx(write=True) as c:
            conv, member = self.service._conversation(c, actor.id, cid, lock=True)
            self.service._can_post(c, actor, conv, member)
            # Serializes per-owner quota and client-id checks across conversations.
            c.execute(select(users.c.id).where(users.c.id == actor.id).with_for_update()).first()
            old = c.execute(select(uploads).where(uploads.c.owner_id == actor.id,
                uploads.c.client_id == client)).mappings().first()
            if old:
                if old['conversation_id'] != cid or old['sha256'] != digest or old['total'] != total:
                    raise Fault(409, 'Upload clientId was already used for different content')
                return {'id': old['id'], 'offset': old['offset'], 'ready': old['ready']}
            used = c.execute(select(func.coalesce(func.sum(uploads.c.total), 0)).where(uploads.c.owner_id == actor.id)).scalar_one()
            if used + total > self.service.settings.user_storage_quota:
                raise Fault(413, 'Account file quota reached; ask the server owner')
            uid = uuid.uuid4().hex
            c.execute(insert(uploads).values(id=uid, owner_id=actor.id, conversation_id=cid,
                client_id=client, name=name, mime=mime, total=total, offset=0, sha256=digest,
                ready=False, created_at=now_ms()))
        return {'id': uid, 'offset': 0, 'ready': False}

    def _owned(self, c, actor, uid, lock=False):
        query = select(uploads).where(uploads.c.id == uid, uploads.c.owner_id == actor.id)
        if lock:
            query = query.with_for_update()
        row = c.execute(query).mappings().first()
        if not row:
            raise Fault(404, 'Upload not found')
        self.service._conversation(c, actor.id, row['conversation_id'])
        return row

    def status(self, actor, uid):
        with self.db.tx() as c:
            row = self._owned(c, actor, uid)
            return {'id': uid, 'offset': row['offset'], 'ready': row['ready']}

    def chunk(self, actor, uid, offset, body):
        integer(offset, 'offset', 0, self.service.settings.max_upload)
        if not body or len(body) > 262144:
            raise Fault(413, 'Chunk must be 1..262144 bytes')
        path = self.path(uid)
        with self.db.tx(write=True) as c:
            preliminary = self._owned(c, actor, uid)
            conv, member = self.service._conversation(c, actor.id, preliminary['conversation_id'], lock=True)
            self.service._can_post(c, actor, conv, member)
            row = self._owned(c, actor, uid, lock=True)
            if row['ready']:
                return {'id': uid, 'offset': row['offset'], 'ready': True}
            if offset != row['offset']:
                # Acknowledgement may have been lost: the client asks for authoritative offset.
                raise Fault(409, 'Offset mismatch; fetch upload status before retrying')
            end = offset + len(body)
            if end > row['total']:
                raise Fault(400, 'Chunk exceeds declared file size')
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists() and offset:
                raise Fault(503, 'Upload storage is unavailable; restore the shared volume')
            with path.open('r+b' if path.exists() else 'w+b') as f:
                f.seek(0, os.SEEK_END)
                if f.tell() < offset:
                    raise Fault(503, 'Upload storage is shorter than its committed offset')
                f.truncate(offset)  # Roll back uncommitted bytes after power loss.
                f.seek(offset)
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            ready = end == row['total']
            if ready:
                with path.open('rb') as f:
                    actual = hashlib.file_digest(f, 'sha256').hexdigest()
                if actual != row['sha256']:
                    # Keep offset at previous committed boundary; caller may resend final chunk.
                    raise Fault(422, 'File SHA-256 mismatch; select the original file again')
            c.execute(update(uploads).where(uploads.c.id == uid).values(offset=end, ready=ready))
        return {'id': uid, 'offset': end, 'ready': ready}

    def download(self, actor, uid):
        with self.db.tx(snapshot=True) as c:
            row = c.execute(select(uploads).join(messages, uploads.c.message_id == messages.c.id)
                .where(uploads.c.id == uid, uploads.c.ready == True, messages.c.deleted == False)).mappings().first()
            if not row:
                raise Fault(404, 'Attachment not found')
            self.service._conversation(c, actor.id, row['conversation_id'])
            path = self.path(uid)
            if not path.is_file() or path.stat().st_size != row['total']:
                raise Fault(503, 'Attachment storage unavailable')
            return path, row['name'], row['sha256']