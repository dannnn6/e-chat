from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import uuid
from sqlalchemy import select, insert, update, delete, and_
from cryptography.exceptions import InvalidSignature
from .db import (Database, users, devices, sessions, challenges, clocks, conversations, members, now_ms)
from .security import public_key, fingerprint, account_id, b64, unb64, verify
from .settings import Settings

class Fault(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def text(value, label: str, maximum: int, *, empty=False) -> str:
    if not isinstance(value, str):
        raise Fault(400, label + ' must be a string')
    value = value.strip()
    if (not value and not empty) or len(value) > maximum or '\x00' in value:
        raise Fault(400, 'Invalid ' + label)
    return value


def integer(value, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise Fault(400, 'Invalid ' + label)
    return value


@dataclass(frozen=True)
class Actor:
    id: str
    name: str
    device_id: str


class Auth:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings

    def challenge(self, data: dict) -> dict:
        mode = data.get('mode')
        if mode not in ('register', 'recover', 'login'):
            raise Fault(400, 'mode must be register, recover or login')
        if mode == 'register':
            token = self.settings.registration_token
            if not token or not hmac.compare_digest(str(data.get('invite', '')), token):
                raise Fault(403, 'Registration requires a valid invitation from the server owner')
        try:
            _, device_der = public_key(data.get('devicePublicKey', ''))
            if mode == 'login':
                uid = text(data.get('accountId'), 'accountId', 44)
                with self.db.tx() as c:
                    row = c.execute(select(users).where(users.c.id == uid)).mappings().first()
                    if not row or row['disabled']:
                        raise Fault(403, 'Account unavailable')
                    root_der = row['public_key']
            else:
                _, root_der = public_key(data.get('rootPublicKey', ''))
                uid = account_id(root_der)
        except (ValueError, TypeError) as exc:
            raise Fault(400, 'Invalid public key') from exc
        payload = {
            'mode': mode, 'accountId': uid, 'rootPublicKey': b64(root_der),
            'devicePublicKey': b64(device_der), 'deviceId': fingerprint(device_der),
            'name': text(data.get('name', 'E-chat'), 'name', 80),
            'deviceName': text(data.get('deviceName', 'Browser'), 'deviceName', 80),
            'revokeOthers': data.get('revokeOthers') is True,
        }
        cid = uuid.uuid4().hex
        encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        # Signature binds origin, purpose, nonce, ALL enrolment fields and revocation policy.
        transcript = '\n'.join(('ECHAT-AUTH-1', self.settings.public_origin, cid,
            secrets.token_urlsafe(32), hashlib.sha256(encoded.encode()).hexdigest()))
        expiry = now_ms() + 120_000
        with self.db.tx(write=True) as c:
            c.execute(delete(challenges).where(challenges.c.expires_at < now_ms()))
            c.execute(insert(challenges).values(id=cid, payload=encoded, transcript=transcript, expires_at=expiry))
        return {'challengeId': cid, 'transcript': transcript, 'accountId': uid, 'expiresAt': expiry, 'payload': payload}

    def complete(self, data: dict) -> dict:
        cid = text(data.get('challengeId'), 'challengeId', 32)
        sig = text(data.get('signature'), 'signature', 512)
        affected = []
        with self.db.tx(write=True) as c:
            challenge = c.execute(select(challenges).where(challenges.c.id == cid).with_for_update()).mappings().first()
            if not challenge or challenge['expires_at'] <= now_ms():
                raise Fault(401, 'Challenge expired or already used')
            p = json.loads(challenge['payload'])
            uid, did, mode = p['accountId'], p['deviceId'], p['mode']
            root, device = unb64(p['rootPublicKey']), unb64(p['devicePublicKey'])
            try:
                verify(device if mode == 'login' else root, challenge['transcript'], sig)
            except (ValueError, InvalidSignature) as exc:
                raise Fault(401, 'Signature verification failed') from exc
            user = c.execute(select(users).where(users.c.id == uid).with_for_update()).mappings().first()
            if mode == 'register':
                if user:
                    raise Fault(409, 'Account already exists; choose recovery')
                c.execute(insert(users).values(id=uid, name=p['name'], public_key=root, disabled=False, created_at=now_ms()))
                c.execute(insert(clocks).values(user_id=uid, revision=0))
                saved = uuid.uuid4().hex
                c.execute(insert(conversations).values(id=saved, kind='saved', title='Избранное',
                    owner_id=uid, creator_id=uid, client_id='saved', last_seq=0, updated_at=now_ms()))
                c.execute(insert(members).values(conversation_id=saved, user_id=uid, role='owner', read_seq=0, muted=False))
                self.db.emit(c, [uid], saved)
                name = p['name']
            else:
                if not user or user['disabled'] or user['public_key'] != root:
                    raise Fault(403, 'Account unavailable')
                name = user['name']
            old_device = c.execute(select(devices).where(devices.c.id == did).with_for_update()).mappings().first()
            if old_device and old_device['user_id'] != uid:
                raise Fault(409, 'Device key belongs to another account')
            if mode == 'login':
                if not old_device or old_device['revoked']:
                    raise Fault(403, 'Device revoked or unknown; use the recovery key')
            else:
                if mode == 'recover' and p['revokeOthers']:
                    other_ids = select(devices.c.id).where(devices.c.user_id == uid)
                    c.execute(delete(sessions).where(sessions.c.device_id.in_(other_ids)))
                    c.execute(update(devices).where(devices.c.user_id == uid).values(revoked=True))
                values = dict(user_id=uid, public_key=device, name=p['deviceName'], revoked=False, created_at=now_ms())
                if old_device:
                    c.execute(update(devices).where(devices.c.id == did).values(**values))
                else:
                    c.execute(insert(devices).values(id=did, **values))
            c.execute(delete(challenges).where(challenges.c.id == cid))
            c.execute(delete(sessions).where(sessions.c.device_id == did))
            token = secrets.token_urlsafe(32)
            expiry = now_ms() + self.settings.session_days * 86_400_000
            c.execute(insert(sessions).values(token_hash=hashlib.sha256(token.encode()).hexdigest(), device_id=did, expires_at=expiry))
        return {'token': token, 'expiresAt': expiry, 'user': {'id': uid, 'name': name}, 'deviceId': did}

    def authenticate(self, token: str) -> Actor:
        if not token or len(token) > 256:
            raise Fault(401, 'Authentication required')
        with self.db.tx() as c:
            row = c.execute(select(users.c.id, users.c.name, devices.c.id.label('device_id'))
                .select_from(sessions.join(devices).join(users))
                .where(sessions.c.token_hash == hashlib.sha256(token.encode()).hexdigest(),
                       sessions.c.expires_at > now_ms(), devices.c.revoked == False, users.c.disabled == False)
            ).mappings().first()
        if not row:
            raise Fault(401, 'Session expired or revoked')
        return Actor(**row)

    def device_list(self, actor: Actor):
        with self.db.tx() as c:
            rows = c.execute(select(devices.c.id, devices.c.name, devices.c.created_at, devices.c.revoked)
                             .where(devices.c.user_id == actor.id).order_by(devices.c.created_at.desc())).mappings().all()
        return {'devices': [dict(id=r['id'], name=r['name'], createdAt=r['created_at'],
            revoked=r['revoked'], current=r['id'] == actor.device_id) for r in rows]}

    def revoke(self, actor: Actor, did: str):
        with self.db.tx(write=True) as c:
            row = c.execute(select(devices.c.id).where(devices.c.id == did, devices.c.user_id == actor.id)).first()
            if not row:
                raise Fault(404, 'Device not found')
            c.execute(update(devices).where(devices.c.id == did).values(revoked=True))
            c.execute(delete(sessions).where(sessions.c.device_id == did))
        return {'ok': True}