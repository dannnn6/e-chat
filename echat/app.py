from __future__ import annotations
import asyncio
import contextlib
import json
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.middleware.gzip import GZipMiddleware
from .settings import Settings
from .db import Database
from .security import Cipher
from .auth import Auth, Fault, text
from .service import Service
from .media import Media

log = logging.getLogger('echat')

class Hub:
    """Wake-ups are hints. Durable cursor polling recovers every missed notification."""
    def __init__(self):
        self.loop = None
        self.waiters = defaultdict(set)
        self.active = defaultdict(int)

    def wake(self, ids):
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self._wake, tuple(ids))

    def _wake(self, ids):
        for uid in ids:
            for e in tuple(self.waiters.get(uid, ())):
                e.set()

    async def listen(self, url):
        # PostgreSQL LISTEN is an acceleration only; 5-second fallback works across nodes.
        if url.startswith('sqlite:'):
            return
        try:
            import psycopg
        except ImportError:
            log.warning('psycopg missing: cross-node notifications use cursor fallback')
            return
        dsn = url.replace('postgresql+psycopg://', 'postgresql://', 1)
        while True:
            try:
                async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
                    await conn.execute('LISTEN echat_changes')
                    async for item in conn.notifies():
                        self._wake([item.payload])
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception('Notification listener reconnecting')
                await asyncio.sleep(5)

class RateLimit:
    """Bounded in-process limiter. Cluster-wide quotas belong at the reverse proxy."""
    def __init__(self):
        self.buckets = {}
        self.next_cleanup = 0.0

    def allow(self, key, maximum, period=60):
        now = time.monotonic()
        if now > self.next_cleanup:
            self.buckets = {k: q for k, q in self.buckets.items() if q and q[-1] > now - 60}
            self.next_cleanup = now + 30
        if key not in self.buckets and len(self.buckets) >= 20000:
            return False
        q = self.buckets.setdefault(key, deque())
        while q and q[0] <= now - period:
            q.popleft()
        if len(q) >= maximum:
            return False
        q.append(now)
        return True

async def body_bytes(request, maximum):
    value = bytearray()
    async for chunk in request.stream():
        value.extend(chunk)
        if len(value) > maximum:
            raise Fault(413, 'Request is too large')
    return bytes(value)

async def json_body(request):
    raw = await body_bytes(request, 65536)
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as e:
        raise Fault(400, 'Invalid JSON') from e
    if not isinstance(data, dict):
        raise Fault(400, 'JSON object required')
    return data

def create_app(settings=None):
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db, cipher, hub, limits = Database(settings.database_url), Cipher(settings.data_key), Hub(), RateLimit()
    auth = Auth(db, settings)
    service = Service(db, cipher, settings, hub.wake)
    media = Media(service)

    @asynccontextmanager
    async def lifespan(app):
        await asyncio.to_thread(db.check)
        hub.loop = asyncio.get_running_loop()
        listener = asyncio.create_task(hub.listen(settings.database_url))
        yield
        listener.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await listener
        db.engine.dispose()

    app = FastAPI(title='E-chat pilot API', version='0.1.0', lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db, app.state.auth, app.state.service, app.state.media = db, auth, service, media
    app.add_middleware(GZipMiddleware, minimum_size=700, compresslevel=4)

    @app.middleware('http')
    async def headers_and_origin(request, call_next):
        origin = request.headers.get('origin')
        if origin and origin != settings.public_origin:
            return JSONResponse({'error': 'Unexpected origin'}, status_code=403)
        ip = request.client.host if request.client else 'unknown'
        bucket = 'auth:' + ip if request.url.path.startswith('/api/auth/') else 'http:' + ip
        if not limits.allow(bucket, 30 if bucket.startswith('auth:') else 1800):
            return JSONResponse({'error': 'Too many requests'}, status_code=429, headers={'Retry-After': '30'})
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        if request.url.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.exception_handler(Fault)
    async def fault_handler(request, error):
        return JSONResponse({'error': error.message}, status_code=error.code)

    @app.exception_handler(IntegrityError)
    async def conflict_handler(request, error):
        log.warning('Concurrent write or constraint conflict')
        return JSONResponse({'error': 'Concurrent write conflict; retry the same clientId'}, status_code=409)

    @app.exception_handler(OperationalError)
    async def operational_handler(request, error):
        log.exception('Database operation unavailable')
        return JSONResponse({'error': 'Storage temporarily unavailable'}, status_code=503)

    @app.exception_handler(Exception)
    async def exception_handler(request, error):
        log.exception('Unhandled request error')
        return JSONResponse({'error': 'Internal error'}, status_code=500)

    def bearer(request):
        value = request.headers.get('authorization', '')
        return value[7:] if value.startswith('Bearer ') else ''

    async def actor_for(request):
        return await asyncio.to_thread(auth.authenticate, bearer(request))

    @app.get('/health/live')
    async def live():
        return {'ok': True, 'version': '0.1.0-pilot'}

    @app.get('/health/ready')
    async def ready():
        await asyncio.to_thread(db.check)
        return {'ok': True}

    @app.post('/api/auth/challenge')
    async def challenge(request: Request):
        return await asyncio.to_thread(auth.challenge, await json_body(request))

    @app.post('/api/auth/complete')
    async def complete(request: Request):
        return await asyncio.to_thread(auth.complete, await json_body(request))

    @app.get('/api/auth/devices')
    async def device_list(request: Request):
        return await asyncio.to_thread(auth.device_list, await actor_for(request))

    @app.post('/api/auth/revoke')
    async def revoke(request: Request):
        actor = await actor_for(request)
        data = await json_body(request)
        return await asyncio.to_thread(auth.revoke, actor, text(data.get('deviceId'), 'deviceId', 64))

    @app.post('/api/rpc')
    async def rpc(request: Request, action: str):
        actor = await actor_for(request)
        if not limits.allow('user:' + actor.id, 360):
            raise Fault(429, 'Account rate limit; retry later')
        data = await json_body(request)
        if action != 'sync' or data.get('cursor') is None:
            return await asyncio.to_thread(service.rpc, actor, action, data)
        wait = data.get('wait', 25)
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not 0 <= wait <= 25:
            raise Fault(400, 'wait must be 0..25 seconds')
        if hub.active[actor.device_id] >= 2:
            raise Fault(429, 'Only two sync requests per device are allowed')
        hub.active[actor.device_id] += 1
        signal = asyncio.Event()
        hub.waiters[actor.id].add(signal)  # Subscribe BEFORE reading the cursor.
        deadline = time.monotonic() + wait
        try:
            while True:
                signal.clear()
                result = await asyncio.to_thread(service.sync, actor, data)
                if result['messages'] or result['conversations'] or result['reset'] or time.monotonic() >= deadline:
                    return result
                if await request.is_disconnected():
                    raise Fault(499, 'Client disconnected')
                try:
                    await asyncio.wait_for(signal.wait(), min(5, max(0.01, deadline-time.monotonic())))
                except asyncio.TimeoutError:
                    pass
                # A revoked device cannot receive a new batch on an old long poll.
                actor = await actor_for(request)
        finally:
            hub.active[actor.device_id] -= 1
            if not hub.active[actor.device_id]:
                hub.active.pop(actor.device_id, None)
            hub.waiters[actor.id].discard(signal)
            if not hub.waiters[actor.id]:
                hub.waiters.pop(actor.id, None)

    @app.post('/api/uploads')
    async def upload_start(request: Request):
        return await asyncio.to_thread(media.start, await actor_for(request), await json_body(request))

    @app.get('/api/uploads/{uid}')
    async def upload_status(request: Request, uid: str):
        return await asyncio.to_thread(media.status, await actor_for(request), uid)

    @app.put('/api/uploads/{uid}')
    async def upload_chunk(request: Request, uid: str, offset: int):
        actor = await actor_for(request)
        return await asyncio.to_thread(media.chunk, actor, uid, offset, await body_bytes(request, 262144))

    @app.get('/api/files/{uid}')
    async def download(request: Request, uid: str):
        path, name, digest = await asyncio.to_thread(media.download, await actor_for(request), uid)
        return FileResponse(path, filename=name, media_type='application/octet-stream',
            headers={'X-Content-SHA256': digest, 'Cache-Control': 'private, no-store'})

    app.mount('/', StaticFiles(directory=Path(__file__).resolve().parent.parent / 'web', html=True), name='web')
    return app