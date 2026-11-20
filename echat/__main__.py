import argparse
import secrets
from .settings import Settings
from .db import Database
from .security import b64

def main():
    parser = argparse.ArgumentParser(description='E-chat server maintenance')
    parser.add_argument('command', choices=['keygen', 'migrate', 'check', 'serve'])
    args = parser.parse_args()
    if args.command == 'keygen':
        print(b64(secrets.token_bytes(32)))
        return
    settings = Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if args.command == 'serve':
        import uvicorn
        uvicorn.run('echat.app:create_app', factory=True, host='0.0.0.0', port=8080,
            proxy_headers=True, forwarded_allow_ips='127.0.0.1', access_log=False)
    else:
        db = Database(settings.database_url)
        getattr(db, args.command)()
        db.engine.dispose()
        print(args.command + ': OK')

if __name__ == '__main__':
    main()