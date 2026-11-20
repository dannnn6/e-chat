#!/usr/bin/env python3
"""Local disposable pilot server, loopback only. Not a production deployment."""
import json, os, sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from echat.security import b64
from echat.settings import Settings
from echat.db import Database
from echat.app import create_app
import uvicorn

def main():
    data=root/'data'/'dev';data.mkdir(parents=True,exist_ok=True,mode=0o700)
    key_path=data/'data-key.txt'
    if not key_path.exists():
        fd=os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(b64(os.urandom(32))+'\n')
    settings=Settings('sqlite:///'+str(data/'echat.db'),key_path.read_text().strip(),data,'http://127.0.0.1:18080','browser-test-invite')
    db=Database(settings.database_url);db.migrate();db.engine.dispose()
    print('LOCAL TEST ONLY: http://127.0.0.1:18080; invitation: browser-test-invite',flush=True)
    print('This directory contains test history and a server data key:',data,flush=True)
    uvicorn.run(create_app(settings),host='127.0.0.1',port=18080,access_log=False)
if __name__=='__main__':main()