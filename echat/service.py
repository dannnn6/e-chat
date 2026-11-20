from __future__ import annotations
import hashlib
import secrets
import uuid
from collections import defaultdict
from sqlalchemy import select, insert, update, delete, func, and_, or_
from .db import (Database, users, clocks, conversations, members, messages, events,
                 uploads, invites, blocks, now_ms)
from .auth import Actor, Fault, text, integer
from .security import Cipher
from .settings import Settings

MAX_TEXT = 4096

class Service:
    def __init__(self, db: Database, cipher: Cipher, settings: Settings, wake=lambda ids: None):
        self.db, self.cipher, self.settings, self.wake = db, cipher, settings, wake

    def _member(self, c, uid, cid):
        row = c.execute(select(members).where(members.c.conversation_id == cid,
                                              members.c.user_id == uid)).mappings().first()
        if not row:
            raise Fault(403, 'You are not a member of this conversation')
        return row

    def _conversation(self, c, uid, cid, *, lock=False):
        query = select(conversations).where(conversations.c.id == cid)
        if lock:
            query = query.with_for_update()
        row = c.execute(query).mappings().first()
        if not row:
            raise Fault(404, 'Conversation not found')
        return row, self._member(c, uid, cid)

    def _ids(self, c, cid):
        return c.execute(select(members.c.user_id).where(members.c.conversation_id == cid)
                         .order_by(members.c.user_id)).scalars().all()

    def _capacity(self, c, uid):
        count = c.execute(select(func.count()).select_from(members).where(members.c.user_id == uid)).scalar_one()
        if count >= self.settings.max_conversations:
            raise Fault(409, 'Pilot conversation limit reached')

    def _blocked(self, c, a, b):
        return c.execute(select(blocks.c.user_id).where(or_(
            and_(blocks.c.user_id == a, blocks.c.peer_id == b),
            and_(blocks.c.user_id == b, blocks.c.peer_id == a)))).first() is not None

    def _can_post(self, c, actor, conv, member):
        if conv['kind'] == 'channel' and member['role'] not in ('owner', 'admin'):
            raise Fault(403, 'Only channel administrators can publish')
        if conv['kind'] == 'direct':
            for peer in self._ids(c, conv['id']):
                if peer != actor.id:
                    enabled = c.execute(select(users.c.id).where(users.c.id == peer, users.c.disabled == False)).first()
                    if not enabled or self._blocked(c, actor.id, peer):
                        raise Fault(403, 'Direct messaging is unavailable for this contact')

    def _hydrate(self, c, rows):
        rows = list(rows)
        if not rows:
            return []
        ids = [r['id'] for r in rows]
        files = defaultdict(list)
        for f in c.execute(select(uploads).where(uploads.c.message_id.in_(ids))).mappings():
            files[f['message_id']].append({'id': f['id'], 'name': f['name'], 'size': f['total'],
                'mime': f['mime'], 'sha256': f['sha256']})
        result = []
        for r in rows:
            result.append({'id': r['id'], 'cid': r['conversation_id'], 'seq': r['seq'],
                'senderId': r['sender_id'], 'senderName': r['sender_name'], 'clientId': r['client_id'],
                'body': '' if r['deleted'] else self.cipher.open(r['body'], r['id']),
                'createdAt': r['created_at'], 'version': r['version'], 'edited': r['edited'],
                'deleted': r['deleted'], 'replyTo': r['reply_to'],
                'attachments': [] if r['deleted'] else files[r['id']]})
        return result

    def _message_query(self):
        return select(messages, users.c.name.label('sender_name')).select_from(messages.join(users, messages.c.sender_id == users.c.id))

    def summaries(self, c, uid, only=None):
        q = select(conversations, members.c.role, members.c.read_seq, members.c.muted).select_from(
            conversations.join(members)).where(members.c.user_id == uid)
        if only is not None:
            if not only:
                return []
            q = q.where(conversations.c.id.in_(only))
        rows = c.execute(q.order_by(conversations.c.updated_at.desc(), conversations.c.id)
                         .limit(self.settings.max_conversations)).mappings().all()
        if not rows:
            return []
        ids = [r['id'] for r in rows]
        latest = {r['conversation_id']: r for r in c.execute(select(messages).join(conversations,
            and_(messages.c.conversation_id == conversations.c.id, messages.c.seq == conversations.c.last_seq))
            .where(conversations.c.id.in_(ids))).mappings()}
        peers = defaultdict(list)
        for r in c.execute(select(members, users.c.name, users.c.disabled).join(users)
                .where(members.c.conversation_id.in_(ids))).mappings():
            peers[r['conversation_id']].append(r)
        unread = {r[0]: r[1] for r in c.execute(select(messages.c.conversation_id, func.count())
            .join(members, and_(messages.c.conversation_id == members.c.conversation_id, members.c.user_id == uid))
            .where(messages.c.conversation_id.in_(ids), messages.c.seq > members.c.read_seq,
                   messages.c.sender_id != uid, messages.c.deleted == False).group_by(messages.c.conversation_id))}
        blocked_ids = set()
        for r in c.execute(select(blocks).where(or_(blocks.c.user_id == uid, blocks.c.peer_id == uid))).mappings():
            blocked_ids.add(r['peer_id'] if r['user_id'] == uid else r['user_id'])
        result = []
        for r in rows:
            ps = [p for p in peers[r['id']] if p['user_id'] != uid]
            peer = ps[0] if r['kind'] == 'direct' and ps else None
            last = latest.get(r['id'])
            preview = '' if not last else ('[deleted]' if last['deleted'] else self.cipher.open(last['body'], last['id'])[:120])
            result.append({'id': r['id'], 'kind': r['kind'], 'title': peer['name'] if peer else r['title'],
                'peerId': peer['user_id'] if peer else None, 'role': r['role'], 'lastSeq': r['last_seq'],
                'readSeq': r['read_seq'], 'peerReadSeq': peer['read_seq'] if peer else 0,
                'updatedAt': r['updated_at'], 'unread': unread.get(r['id'], 0), 'lastText': preview,
                'muted': r['muted'], 'memberCount': len(peers[r['id']]), 'removed': False,
                'canSend': (r['kind'] != 'channel' or r['role'] in ('admin', 'owner')) and
                           (not peer or (not peer['disabled'] and peer['user_id'] not in blocked_ids))})
        return result

    def sync(self, actor: Actor, data: dict):
        cursor = data.get('cursor')
        if cursor is not None:
            integer(cursor, 'cursor', 0, 2**53 - 1)
        limit = integer(data.get('limit', 50), 'limit', 1, 100)
        with self.db.tx(snapshot=True) as c:
            revision = c.execute(select(clocks.c.revision).where(clocks.c.user_id == actor.id)).scalar_one()
            if cursor is None or cursor > revision:
                return {'cursor': revision, 'reset': True, 'more': False,
                        'conversations': self.summaries(c, actor.id), 'messages': []}
            rows = c.execute(select(events).where(events.c.user_id == actor.id, events.c.revision > cursor)
                             .order_by(events.c.revision).limit(limit + 1)).mappings().all()
            more = len(rows) > limit
            rows = rows[:limit]
            if not rows:
                return {'cursor': cursor, 'reset': False, 'more': False, 'conversations': [], 'messages': []}
            cids = set(r['conversation_id'] for r in rows)
            summaries = self.summaries(c, actor.id, cids)
            allowed = set(r['id'] for r in summaries)
            summaries.extend({'id': cid, 'removed': True} for cid in sorted(cids - allowed))
            mids = set(r['message_id'] for r in rows if r['message_id'] and r['conversation_id'] in allowed)
            body_rows = c.execute(self._message_query().where(messages.c.id.in_(mids))).mappings().all() if mids else []
            return {'cursor': rows[-1]['revision'], 'reset': False, 'more': more,
                    'conversations': summaries, 'messages': self._hydrate(c, body_rows)}

    def peers(self, actor, data):
        uid = text(data.get('query', ''), 'query', 44)
        with self.db.tx() as c:
            rows = c.execute(select(users.c.id, users.c.name).where(users.c.id == uid, users.c.disabled == False)).mappings().all()
        return {'users': [dict(r) for r in rows]}

    def create(self, actor, data):
        kind = data.get('kind', 'direct')
        if kind not in ('direct', 'group', 'channel'):
            raise Fault(400, 'Invalid conversation kind')
        cid = uuid.uuid4().hex
        client_id = text(data.get('clientId'), 'clientId', 64)
        title_value = text(data.get('title', ''), 'title', 120, empty=kind == 'direct')
        affected = [actor.id]
        with self.db.tx(write=True) as c:
            # Canonical user-lock order also serializes simultaneous A->B and B->A creation.
            lock_ids = [actor.id]
            if kind == 'direct':
                lock_ids.append(text(data.get('peerId'), 'peerId', 44))
            c.execute(select(users.c.id).where(users.c.id.in_(sorted(set(lock_ids))))
                      .order_by(users.c.id).with_for_update()).all()
            prior = c.execute(select(conversations.c.id).where(conversations.c.creator_id == actor.id,
                conversations.c.client_id == client_id)).scalar_one_or_none()
            if prior:
                summary = self.summaries(c, actor.id, [prior])
                if not summary:
                    raise Fault(409, 'This creation request belongs to a conversation you have left')
                return {'conversation': summary[0], 'duplicate': True}
            direct_key = None
            if kind == 'direct':
                peer = text(data.get('peerId'), 'peerId', 44)
                if peer == actor.id:
                    saved = c.execute(select(conversations.c.id).where(conversations.c.owner_id == actor.id,
                        conversations.c.kind == 'saved')).scalar_one()
                    return {'conversation': self.summaries(c, actor.id, [saved])[0]}
                user = c.execute(select(users.c.id).where(users.c.id == peer, users.c.disabled == False)).first()
                if not user or self._blocked(c, actor.id, peer):
                    raise Fault(403, 'Contact unavailable')
                affected.append(peer)
                direct_key = ':'.join(sorted(affected))
                prior = c.execute(select(conversations.c.id).where(conversations.c.direct_key == direct_key)).scalar_one_or_none()
                if prior:
                    return {'conversation': self.summaries(c, actor.id, [prior])[0], 'duplicate': True}
                self._capacity(c, peer)
            self._capacity(c, actor.id)
            c.execute(insert(conversations).values(id=cid, kind=kind, title=title_value, owner_id=actor.id, creator_id=actor.id,
                client_id=client_id, direct_key=direct_key, last_seq=0, updated_at=now_ms()))
            for uid in affected:
                c.execute(insert(members).values(conversation_id=cid, user_id=uid,
                    role='owner' if uid == actor.id else 'member', read_seq=0, muted=False))
            self.db.emit(c, affected, cid)
            result = {'conversation': self.summaries(c, actor.id, [cid])[0]}
        self.wake(affected)
        return result

    def history(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        limit = integer(data.get('limit', 50), 'limit', 1, 100)
        before = data.get('beforeSeq')
        if before is not None:
            integer(before, 'beforeSeq', 1, 2**53 - 1)
        with self.db.tx(snapshot=True) as c:
            self._conversation(c, actor.id, cid)
            q = self._message_query().where(messages.c.conversation_id == cid)
            if before is not None:
                q = q.where(messages.c.seq < before)
            rows = c.execute(q.order_by(messages.c.seq.desc()).limit(limit + 1)).mappings().all()
            more = len(rows) > limit
            return {'messages': self._hydrate(c, reversed(rows[:limit])), 'more': more,
                    'conversation': self.summaries(c, actor.id, [cid])[0]}

    def send(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        client_id = text(data.get('clientId'), 'clientId', 64)
        body = text(data.get('body', ''), 'body', MAX_TEXT, empty=True)
        file_ids = data.get('attachmentIds', [])
        if not isinstance(file_ids, list) or len(file_ids) > 4 or any(not isinstance(x, str) or len(x) != 32 for x in file_ids):
            raise Fault(400, 'At most four valid attachments are allowed')
        file_ids = sorted(set(file_ids))
        if not body and not file_ids:
            raise Fault(400, 'Message is empty')
        mid = uuid.uuid4().hex
        with self.db.tx(write=True) as c:
            conv, member = self._conversation(c, actor.id, cid, lock=True)
            self._can_post(c, actor, conv, member)
            prior = c.execute(self._message_query().where(messages.c.sender_id == actor.id,
                messages.c.client_id == client_id)).mappings().first()
            if prior:
                if prior['conversation_id'] != cid:
                    raise Fault(409, 'clientId already used in another conversation')
                return {'message': self._hydrate(c, [prior])[0], 'duplicate': True}
            reply = data.get('replyTo')
            if reply is not None:
                text(reply, 'replyTo', 32)
                if not c.execute(select(messages.c.id).where(messages.c.id == reply,
                    messages.c.conversation_id == cid, messages.c.deleted == False)).first():
                    raise Fault(400, 'Reply target must belong to this conversation')
            if file_ids:
                fs = c.execute(select(uploads).where(uploads.c.id.in_(file_ids)).with_for_update()).mappings().all()
                if len(fs) != len(file_ids) or any(f['owner_id'] != actor.id or f['conversation_id'] != cid
                    or not f['ready'] or f['message_id'] for f in fs):
                    raise Fault(400, 'Attachment unavailable or already attached')
            seq = conv['last_seq'] + 1
            timestamp = now_ms()
            c.execute(insert(messages).values(id=mid, conversation_id=cid, seq=seq, sender_id=actor.id,
                client_id=client_id, body=self.cipher.seal(body, mid), created_at=timestamp,
                version=1, edited=False, deleted=False, reply_to=reply))
            if file_ids:
                c.execute(update(uploads).where(uploads.c.id.in_(file_ids)).values(message_id=mid))
            c.execute(update(conversations).where(conversations.c.id == cid).values(last_seq=seq, updated_at=timestamp))
            affected = self._ids(c, cid)
            self.db.emit(c, affected, cid, mid)
            result = {'message': self._hydrate(c, c.execute(self._message_query().where(messages.c.id == mid)).mappings())[0]}
        self.wake(affected)
        return result

    def read(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        seq = integer(data.get('seq'), 'seq', 0, 2**53 - 1)
        with self.db.tx(write=True) as c:
            conv, member = self._conversation(c, actor.id, cid, lock=True)
            seq = min(seq, conv['last_seq'])
            if seq <= member['read_seq']:
                return {'ok': True}
            c.execute(update(members).where(members.c.conversation_id == cid, members.c.user_id == actor.id).values(read_seq=seq))
            affected = self._ids(c, cid) if conv['kind'] == 'direct' else [actor.id]
            self.db.emit(c, affected, cid)
        self.wake(affected)
        return {'ok': True}

    def edit(self, actor, data, *, deleting=False):
        cid = text(data.get('cid'), 'cid', 32)
        mid = text(data.get('messageId'), 'messageId', 32)
        body = '' if deleting else text(data.get('body'), 'body', MAX_TEXT)
        with self.db.tx(write=True) as c:
            conv, member = self._conversation(c, actor.id, cid, lock=True)
            row = c.execute(select(messages).where(messages.c.id == mid, messages.c.conversation_id == cid)).mappings().first()
            if not row:
                raise Fault(404, 'Message not found')
            if row['sender_id'] != actor.id and not (deleting and conv['kind'] in ('group', 'channel') and member['role'] in ('owner', 'admin')):
                raise Fault(403, 'Not allowed to change this message')
            if row['deleted']:
                if deleting:
                    return {'ok': True}
                raise Fault(409, 'Message was deleted')
            c.execute(update(messages).where(messages.c.id == mid).values(body=self.cipher.seal(body, mid),
                version=row['version'] + 1, edited=not deleting, deleted=deleting))
            affected = self._ids(c, cid)
            self.db.emit(c, affected, cid, mid)
        self.wake(affected)
        return {'ok': True}

    def member_list(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        with self.db.tx() as c:
            self._conversation(c, actor.id, cid)
            rows = c.execute(select(users.c.id, users.c.name, members.c.role).select_from(members.join(users))
                .where(members.c.conversation_id == cid).order_by(users.c.name)).mappings().all()
        return {'members': [dict(r) for r in rows]}

    def member_change(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        target = text(data.get('userId'), 'userId', 44)
        op = data.get('op')
        if op not in ('add', 'remove', 'promote', 'demote', 'transfer'):
            raise Fault(400, 'Invalid membership operation')
        with self.db.tx(write=True) as c:
            conv, mine = self._conversation(c, actor.id, cid, lock=True)
            if conv['kind'] not in ('group', 'channel'):
                raise Fault(400, 'Direct conversation membership is fixed')
            affected = self._ids(c, cid)
            target_row = c.execute(select(members).where(members.c.conversation_id == cid,
                members.c.user_id == target)).mappings().first()
            leaving = op == 'remove' and target == actor.id
            if not leaving and mine['role'] not in ('owner', 'admin'):
                raise Fault(403, 'Administrator role required')
            if op in ('promote', 'demote', 'transfer') and mine['role'] != 'owner':
                raise Fault(403, 'Only the owner can change administrator roles')
            if op == 'add':
                if target_row:
                    return {'ok': True}
                if len(affected) >= self.settings.max_members:
                    raise Fault(409, 'Pilot membership limit reached')
                if not c.execute(select(users.c.id).where(users.c.id == target, users.c.disabled == False)).first() or self._blocked(c, actor.id, target):
                    raise Fault(403, 'Contact unavailable')
                c.execute(select(users.c.id).where(users.c.id == target).with_for_update()).first()
                self._capacity(c, target)
                c.execute(insert(members).values(conversation_id=cid, user_id=target, role='member', read_seq=0, muted=False))
                affected.append(target)
            else:
                if not target_row:
                    raise Fault(404, 'Member not found')
                if target_row['role'] == 'owner':
                    raise Fault(409, 'Transfer ownership before leaving; the owner cannot be removed')
                if mine['role'] != 'owner' and not leaving and target_row['role'] != 'member':
                    raise Fault(403, 'An administrator cannot remove another administrator')
                where = and_(members.c.conversation_id == cid, members.c.user_id == target)
                if op == 'remove':
                    c.execute(delete(members).where(where))
                else:
                    role = 'owner' if op == 'transfer' else ('admin' if op == 'promote' else 'member')
                    c.execute(update(members).where(where).values(role=role))
                    if op == 'transfer':
                        c.execute(update(members).where(members.c.conversation_id == cid, members.c.user_id == actor.id).values(role='admin'))
                        c.execute(update(conversations).where(conversations.c.id == cid).values(owner_id=target))
            self.db.emit(c, affected, cid)
        self.wake(affected)
        return {'ok': True}

    def invitation(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        token = secrets.token_urlsafe(24)
        with self.db.tx(write=True) as c:
            conv, member = self._conversation(c, actor.id, cid, lock=True)
            if conv['kind'] not in ('group', 'channel') or member['role'] not in ('owner', 'admin'):
                raise Fault(403, 'Administrator role required')
            # Issuing a new invite revokes the previous one for this conversation.
            c.execute(delete(invites).where(invites.c.conversation_id == cid))
            c.execute(insert(invites).values(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                conversation_id=cid, expires_at=now_ms()+86_400_000, uses_left=100))
        return {'invite': token, 'expiresInSeconds': 86400}

    def join(self, actor, data):
        token = text(data.get('invite'), 'invite', 128)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.db.tx(write=True) as c:
            invite = c.execute(select(invites).where(invites.c.token_hash == token_hash)).mappings().first()
            if not invite:
                raise Fault(404, 'Invitation not found')
            cid = invite['conversation_id']
            conv = c.execute(select(conversations).where(conversations.c.id == cid).with_for_update()).mappings().one()
            invite = c.execute(select(invites).where(invites.c.token_hash == token_hash).with_for_update()).mappings().first()
            if not invite or invite['expires_at'] <= now_ms() or invite['uses_left'] <= 0:
                raise Fault(410, 'Invitation expired')
            affected = self._ids(c, cid)
            if actor.id not in affected:
                if len(affected) >= self.settings.max_members:
                    raise Fault(409, 'Pilot membership limit reached')
                if self._blocked(c, actor.id, conv['owner_id']):
                    raise Fault(403, 'Contact unavailable')
                c.execute(select(users.c.id).where(users.c.id == actor.id).with_for_update()).first()
                self._capacity(c, actor.id)
                c.execute(insert(members).values(conversation_id=cid, user_id=actor.id, role='member', read_seq=0, muted=False))
                c.execute(update(invites).where(invites.c.token_hash == token_hash).values(uses_left=invite['uses_left']-1))
                affected.append(actor.id)
                self.db.emit(c, affected, cid)
            result = {'conversation': self.summaries(c, actor.id, [cid])[0]}
        self.wake(affected)
        return result

    def mute(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        if not isinstance(data.get('muted'), bool):
            raise Fault(400, 'muted must be boolean')
        with self.db.tx(write=True) as c:
            self._conversation(c, actor.id, cid, lock=True)
            c.execute(update(members).where(members.c.conversation_id == cid, members.c.user_id == actor.id).values(muted=data['muted']))
            self.db.emit(c, [actor.id], cid)
        self.wake([actor.id])
        return {'ok': True}

    def block(self, actor, data):
        peer = text(data.get('peerId'), 'peerId', 44)
        if peer == actor.id or not isinstance(data.get('blocked'), bool):
            raise Fault(400, 'Invalid block request')
        with self.db.tx(write=True) as c:
            if not c.execute(select(users.c.id).where(users.c.id == peer)).first():
                raise Fault(404, 'User not found')
            c.execute(delete(blocks).where(blocks.c.user_id == actor.id, blocks.c.peer_id == peer))
            if data['blocked']:
                c.execute(insert(blocks).values(user_id=actor.id, peer_id=peer))
            cid = c.execute(select(conversations.c.id).where(conversations.c.direct_key == ':'.join(sorted([actor.id, peer])))).scalar_one_or_none()
            if cid:
                self.db.emit(c, [actor.id, peer], cid)
        self.wake([actor.id, peer])
        return {'ok': True}

    def search(self, actor, data):
        cid = text(data.get('cid'), 'cid', 32)
        term = text(data.get('query'), 'query', 120).casefold().replace('ё', 'е')
        before = integer(data.get('beforeSeq', 2**53-1), 'beforeSeq', 1, 2**53-1)
        with self.db.tx(snapshot=True) as c:
            self._conversation(c, actor.id, cid)
            rows = c.execute(self._message_query().where(messages.c.conversation_id == cid,
                messages.c.seq < before, messages.c.deleted == False).order_by(messages.c.seq.desc()).limit(501)).mappings().all()
            found, scanned, last = [], 0, None
            for row in rows[:500]:
                scanned += 1
                last = row['seq']
                if term in self.cipher.open(row['body'], row['id']).casefold().replace('ё', 'е'):
                    found.append(row)
                if len(found) >= 50:
                    break
            return {'messages': self._hydrate(c, found), 'more': len(rows) > scanned, 'nextBefore': last}

    def rpc(self, actor: Actor, action: str, data: dict):
        functions = {'sync': self.sync, 'peers': self.peers, 'create': self.create,
            'history': self.history, 'send': self.send, 'read': self.read,
            'edit': self.edit, 'members': self.member_list, 'member': self.member_change,
            'invite': self.invitation, 'join': self.join, 'mute': self.mute, 'block': self.block,
            'search': self.search}
        if action == 'delete':
            return self.edit(actor, data, deleting=True)
        fn = functions.get(action)
        if not fn:
            raise Fault(404, 'Unknown action')
        return fn(actor, data)