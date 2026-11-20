import hashlib
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy import select, update
from echat.app import create_app
from echat.db import Database, messages, sessions, devices, challenges, now_ms
from echat.settings import Settings
from echat.security import b64, account_id
from echat.auth import Fault


def public(key):
    return b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

def signed(key, transcript):
    return b64(key.sign(transcript.encode(), ec.ECDSA(hashes.SHA256())))

@pytest.fixture
def client(tmp_path):
    settings = Settings('sqlite:///' + str(tmp_path / 'test.db'), b64(os.urandom(32)), tmp_path, 'http://testserver', 'test-invite')
    app = create_app(settings)
    app.state.db.migrate()
    with TestClient(app) as c:
        yield c


def account(client, name='Alice', root=None, mode='register', revoke=False):
    root = root or ec.generate_private_key(ec.SECP256R1())
    device = ec.generate_private_key(ec.SECP256R1())
    ch = client.post('/api/auth/challenge', json=dict(mode=mode, name=name, deviceName='test',
        rootPublicKey=public(root), devicePublicKey=public(device), invite='test-invite', revokeOthers=revoke))
    assert ch.status_code == 200, ch.text
    body = ch.json()
    response = client.post('/api/auth/complete', json={'challengeId': body['challengeId'], 'signature': signed(root, body['transcript'])})
    assert response.status_code == 200, response.text
    data = response.json()
    data['headers'] = {'Authorization': 'Bearer ' + data['token']}
    data['root'], data['private'] = root, device
    return data


def rpc(c, user, action, expected=200, **data):
    response = c.post('/api/rpc?action=' + action, json=data, headers=user['headers'])
    assert response.status_code == expected, (action, response.status_code, response.text)
    return response.json()


def direct(c, a, b):
    return rpc(c, a, 'create', kind='direct', peerId=b['user']['id'], clientId=str(uuid.uuid4()))['conversation']['id']

def send(c, a, cid, body='Hello', **kw):
    return rpc(c, a, 'send', cid=cid, body=body, clientId=kw.pop('clientId', str(uuid.uuid4())), **kw)['message']


def test_registration_and_recovery(client):
    a = account(client)
    b = account(client, root=a['root'], mode='recover')
    assert a['user']['id'] == b['user']['id']
    assert a['deviceId'] != b['deviceId']
    r = client.get('/api/auth/devices', headers=b['headers'])
    assert len(r.json()['devices']) == 2
    account(client, root=a['root'], mode='recover', revoke=True)
    assert client.get('/api/auth/devices', headers=a['headers']).status_code == 401
    assert client.get('/api/auth/devices', headers=b['headers']).status_code == 401


def test_replay_and_wrong_key_rejected(client):
    a = account(client)
    ch = client.post('/api/auth/challenge', json=dict(mode='login', accountId=a['user']['id'], devicePublicKey=public(a['private']))).json()
    payload = {'challengeId':ch['challengeId'], 'signature':signed(a['root'],ch['transcript'])}
    assert client.post('/api/auth/complete',json=payload).status_code == 401
    payload['signature'] = signed(a['private'],ch['transcript'])
    assert client.post('/api/auth/complete',json=payload).status_code == 200
    assert client.post('/api/auth/complete',json=payload).status_code == 401
    assert client.get('/api/auth/devices',headers=a['headers']).status_code == 401


def test_direct_idempotency_acl_and_read(client):
    a,b,x = account(client),account(client,'Bob'),account(client,'Eve')
    cid=direct(client,a,b)
    assert direct(client,b,a)==cid
    client_id=str(uuid.uuid4())
    first=send(client,a,cid,clientId=client_id)
    assert send(client,a,cid,clientId=client_id)['id']==first['id']
    rpc(client,x,'history',expected=403,cid=cid)
    rpc(client,x,'send',expected=403,cid=cid,body='evil',clientId='evil')
    rpc(client,b,'read',cid=cid,seq=first['seq'])
    rpc(client,b,'read',cid=cid,seq=0)
    assert rpc(client,a,'history',cid=cid)['conversation']['peerReadSeq']==first['seq']
    assert len(rpc(client,b,'history',cid=cid)['messages'])==1


def test_edit_delete_delta_and_wrong_reply(client):
    a,b,x=account(client),account(client,'Bob'),account(client,'Eve')
    cid=direct(client,a,b)
    other=direct(client,a,x)
    m=send(client,a,cid)
    cursor=rpc(client,b,'sync',cursor=None)['cursor']
    rpc(client,b,'edit',expected=403,cid=cid,messageId=m['id'],body='stolen')
    rpc(client,a,'edit',cid=cid,messageId=m['id'],body='Changed')
    delta=rpc(client,b,'sync',cursor=cursor,wait=0)
    assert delta['messages'][0]['body']=='Changed'
    rpc(client,a,'send',expected=400,cid=other,body='cross',clientId='cross',replyTo=m['id'])
    rpc(client,a,'delete',cid=cid,messageId=m['id'])
    delta=rpc(client,b,'sync',cursor=delta['cursor'],wait=0)
    assert delta['messages'][0]['deleted'] and delta['messages'][0]['body']==''


def test_channel_roles_invites_and_removal(client):
    owner, reader=account(client),account(client,'Reader')
    cid=rpc(client,owner,'create',kind='channel',title='Updates',clientId='channel')['conversation']['id']
    invite=rpc(client,owner,'invite',cid=cid)['invite']
    rpc(client,reader,'join',invite=invite)
    rpc(client,reader,'send',expected=403,cid=cid,body='no',clientId='no')
    send(client,owner,cid)
    rpc(client,owner,'member',cid=cid,userId=reader['user']['id'],op='promote')
    send(client,reader,cid,'Admin post')
    cursor=rpc(client,reader,'sync',cursor=None)['cursor']
    rpc(client,owner,'member',cid=cid,userId=reader['user']['id'],op='remove')
    delta=rpc(client,reader,'sync',cursor=cursor,wait=0)
    assert delta['conversations']==[{'id':cid,'removed':True}]
    assert delta['messages']==[]
    rpc(client,reader,'history',expected=403,cid=cid)


def test_block_and_owner_transfer(client):
    a,b=account(client),account(client,'Bob')
    cid=direct(client,a,b)
    rpc(client,b,'block',peerId=a['user']['id'],blocked=True)
    rpc(client,a,'send',expected=403,cid=cid,body='blocked',clientId='blocked')
    rpc(client,b,'block',peerId=a['user']['id'],blocked=False)
    send(client,a,cid)
    group=rpc(client,a,'create',kind='group',title='Group',clientId='g')['conversation']['id']
    rpc(client,a,'member',cid=group,userId=b['user']['id'],op='add')
    rpc(client,a,'member',expected=409,cid=group,userId=a['user']['id'],op='remove')
    rpc(client,a,'member',cid=group,userId=b['user']['id'],op='transfer')
    rpc(client,a,'member',cid=group,userId=a['user']['id'],op='remove')
    assert rpc(client,b,'history',cid=group)['conversation']['role']=='owner'


def test_cursor_pagination_no_missing(client):
    a,b=account(client),account(client,'Bob')
    cid=direct(client,a,b)
    cursor=rpc(client,b,'sync',cursor=None)['cursor']
    sent=[send(client,a,cid,str(i))['id'] for i in range(17)]
    got=[]
    while True:
        batch=rpc(client,b,'sync',cursor=cursor,limit=3,wait=0)
        got.extend(m['id'] for m in batch['messages'])
        assert batch['cursor']>=cursor
        cursor=batch['cursor']
        if not batch['more']:break
    assert set(got)==set(sent) and len(got)==17


def test_concurrent_sends_are_unique_and_sequential(client):
    a,b=account(client),account(client,'Bob')
    cid=direct(client,a,b)
    service=client.app.state.service
    actor=client.app.state.auth.authenticate(a['token'])
    def work(i):
        return service.send(actor,{'cid':cid,'clientId':'parallel-'+str(i),'body':str(i)})['message']
    with ThreadPoolExecutor(max_workers=6) as pool:
        results=list(pool.map(work,range(24)))
    assert sorted(r['seq'] for r in results)==list(range(1,25))
    with ThreadPoolExecutor(max_workers=6) as pool:
        duplicates=list(pool.map(lambda _:work(0),range(8)))
    assert len({r['id'] for r in duplicates})==1


def test_resumable_file_and_acl(client):
    a,b,x=account(client),account(client,'Bob'),account(client,'Eve')
    cid=direct(client,a,b)
    blob=b'abcdef'*1000
    data=dict(cid=cid,clientId='file-1',name='hello.txt',mime='text/plain',total=len(blob),sha256=hashlib.sha256(blob).hexdigest())
    start=client.post('/api/uploads',json=data,headers=a['headers'])
    assert start.status_code==200,start.text
    uid=start.json()['id']
    first=client.put('/api/uploads/'+uid+'?offset=0',content=blob[:3000],headers=a['headers'])
    assert first.json()['offset']==3000
    retry=client.put('/api/uploads/'+uid+'?offset=0',content=blob[:3000],headers=a['headers'])
    assert retry.status_code==409
    assert client.post('/api/uploads',json=data,headers=a['headers']).json()['offset']==3000
    assert client.get('/api/files/'+uid,headers=b['headers']).status_code==404
    assert client.put('/api/uploads/'+uid+'?offset=3000',content=blob[3000:],headers=a['headers']).json()['ready']
    m=send(client,a,cid,body='',attachmentIds=[uid])
    assert client.get('/api/files/'+uid,headers=b['headers']).content==blob
    assert client.get('/api/files/'+uid,headers=x['headers']).status_code==403
    r=client.get('/api/files/'+uid,headers={**b['headers'],'Range':'bytes=10-29'})
    assert r.status_code==206 and r.content==blob[10:30]
    rpc(client,a,'delete',cid=cid,messageId=m['id'])
    assert client.get('/api/files/'+uid,headers=b['headers']).status_code==404


def test_validation_and_origin(client):
    assert client.post('/api/auth/challenge',json={'mode':'register'}).status_code==403
    assert client.post('/api/auth/challenge',json={},headers={'Origin':'https://evil.example'}).status_code==403
    a=account(client)
    rpc(client,a,'sync',expected=400,cursor=-1,wait=0)
    rpc(client,a,'sync',expected=400,cursor=0,wait=999)
    assert client.post('/api/rpc?action=sync',content=b'x'*70000,headers=a['headers']).status_code==413


def test_message_storage_is_encrypted(client):
    a=account(client)
    cid=rpc(client,a,'sync',cursor=None)['conversations'][0]['id']
    m=send(client,a,cid,'A unique secret text')
    with client.app.state.db.tx() as c:
        stored=c.execute(select(messages.c.body).where(messages.c.id==m['id'])).scalar_one()
    assert b'A unique secret text' not in stored
    assert rpc(client,a,'history',cid=cid)['messages'][0]['body']=='A unique secret text'


def test_long_poll_wakes_after_commit(client):
    import time
    a,b=account(client),account(client,'Bob')
    cid=direct(client,a,b)
    cursor=rpc(client,b,'sync',cursor=None)['cursor']
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(lambda:rpc(client,b,'sync',cursor=cursor,wait=3))
        time.sleep(.15)
        m=send(client,a,cid,'wake')
        result=future.result(timeout=5)
    assert result['messages'][0]['id']==m['id']