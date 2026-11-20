#!/usr/bin/env python3
"""Create secrets once. Never replaces an existing .env or rotates a data encryption key."""
import argparse, base64, os, re, secrets
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('domain',help='E-chat HTTPS hostname, e.g. echat.example.com');a=p.parse_args()
    domain=a.domain.lower().rstrip('.')
    if len(domain)>253 or '.' not in domain or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in domain.split('.')):
        p.error('Use a DNS hostname without https://, port, slash, or shell characters')
    root=Path(__file__).resolve().parents[1];target=root/'.env'
    values=dict(COMPOSE_PROJECT_NAME='echat',ECHAT_HOST=domain,ECHAT_PUBLIC_ORIGIN='https://'+domain,
        POSTGRES_PASSWORD=secrets.token_hex(32),ECHAT_DB_PASSWORD=secrets.token_hex(32),
        ECHAT_DATA_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode(),
        ECHAT_REGISTRATION_TOKEN=secrets.token_hex(24),ECHAT_BIND='127.0.0.1',ECHAT_PORT='3080',ECHAT_WORKERS='2',ECHAT_TRUSTED_PROXIES='127.0.0.1')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:f.write(''.join(k+'='+v+'\n' for k,v in values.items()))
    print('Created',target,'with mode 0600. Keep a protected offline copy.')
    print('Registration invitation:',values['ECHAT_REGISTRATION_TOKEN'])
    print('Next: bash scripts/up.sh')
if __name__=='__main__':main()