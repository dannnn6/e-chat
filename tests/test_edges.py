"""Additional ACL and pagination regressions; no production data is used."""
import hashlib
from test_core import client, account, rpc, send, direct


def test_create_retry_after_owner_transfer(client):
    a,b=account(client),account(client,'Bob')
    cid=rpc(client,a,'create',kind='group',title='Stable request',clientId='stable-create')['conversation']['id']
    rpc(client,a,'member',cid=cid,userId=b['user']['id'],op='add')
    rpc(client,a,'member',cid=cid,userId=b['user']['id'],op='transfer')
    again=rpc(client,a,'create',kind='group',title='Stable request',clientId='stable-create')['conversation']['id']
    assert again==cid


def test_channel_demotion_stops_inflight_upload(client):
    owner,admin=account(client),account(client,'Admin')
    cid=rpc(client,owner,'create',kind='channel',title='News',clientId='news')['conversation']['id']
    rpc(client,owner,'member',cid=cid,userId=admin['user']['id'],op='add')
    rpc(client,owner,'member',cid=cid,userId=admin['user']['id'],op='promote')
    blob=b'first-second'
    upload=client.post('/api/uploads',headers=admin['headers'],json=dict(cid=cid,clientId='chunked',name='x.txt',total=len(blob),sha256=hashlib.sha256(blob).hexdigest())).json()['id']
    assert client.put('/api/uploads/'+upload+'?offset=0',headers=admin['headers'],content=blob[:5]).status_code==200
    rpc(client,owner,'member',cid=cid,userId=admin['user']['id'],op='demote')
    assert client.put('/api/uploads/'+upload+'?offset=5',headers=admin['headers'],content=blob[5:]).status_code==403


def test_search_is_bounded_and_continuable(client):
    a,b=account(client),account(client,'Bob');cid=direct(client,a,b)
    expected={send(client,a,cid,'match '+str(i))['id'] for i in range(75)}
    first=rpc(client,b,'search',cid=cid,query='match')
    assert len(first['messages'])==50 and first['more']
    second=rpc(client,b,'search',cid=cid,query='match',beforeSeq=first['nextBefore'])
    assert len(second['messages'])==25
    assert {m['id'] for m in first['messages']+second['messages']}==expected