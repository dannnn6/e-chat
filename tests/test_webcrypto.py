"""Real Node WebCrypto interoperability, not a browser UI test."""
import json
import shutil
import subprocess
from pathlib import Path
import pytest
from test_core import client

HELPER=Path(__file__).with_name('webcrypto_helper.cjs')
pytestmark=pytest.mark.skipif(not shutil.which('node'),reason='Node.js 22+ is required for WebCrypto interoperability tests')

def node(payload):
    r=subprocess.run(['node',str(HELPER)],input=json.dumps(payload,ensure_ascii=False),text=True,capture_output=True,timeout=15)
    assert r.returncode==0,r.stderr
    return json.loads(r.stdout)


def test_raw_webcrypto_signature_and_cyrillic_challenge(client):
    keys=node({'op':'keys'})
    payload=dict(mode='register',rootPublicKey=keys['rootPublicKey'],devicePublicKey=keys['devicePublicKey'],name='Алиса Ёж 🚀',deviceName='Браузер',invite='test-invite',revokeOthers=False)
    r=client.post('/api/auth/challenge',json=payload)
    assert r.status_code==200,r.text
    challenge=r.json()
    assert node({'op':'validate','origin':'http://testserver','challenge':challenge,'expected':{k:payload[k] for k in ('mode','rootPublicKey','devicePublicKey','name')}})['valid']
    signature=node({'op':'sign','privateKey':keys['rootPrivateKey'],'transcript':challenge['transcript']})['signature']
    result=client.post('/api/auth/complete',json={'challengeId':challenge['challengeId'],'signature':signature})
    assert result.status_code==200,result.text
    assert result.json()['user']['name']=='Алиса Ёж 🚀'


def test_web_client_rejects_tampered_or_cross_origin_challenge(client):
    keys=node({'op':'keys'})
    r=client.post('/api/auth/challenge',json=dict(mode='register',rootPublicKey=keys['rootPublicKey'],devicePublicKey=keys['devicePublicKey'],name='Alice',invite='test-invite'))
    challenge=r.json()
    wrong=node({'op':'validate','origin':'https://other.example','challenge':challenge,'expected':{}})
    assert wrong['valid'] is False
    challenge['payload']['name']='Changed by intermediary'
    changed=node({'op':'validate','origin':'http://testserver','challenge':challenge,'expected':{}})
    assert changed['valid'] is False