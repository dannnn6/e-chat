from dataclasses import dataclass
from pathlib import Path
import os

@dataclass(frozen=True)
class Settings:
    database_url: str
    data_key: str
    data_dir: Path
    public_origin: str
    registration_token: str
    max_members: int = 256
    max_conversations: int = 200
    max_upload: int = 10 * 1024 * 1024
    user_storage_quota: int = 100 * 1024 * 1024
    session_days: int = 30

    @classmethod
    def from_env(cls):
        origin = os.environ.get('ECHAT_PUBLIC_ORIGIN', 'http://localhost:8080').rstrip('/')
        if not origin.startswith(('https://', 'http://localhost:', 'http://127.0.0.1:')):
            raise ValueError('Public deployments require HTTPS')
        return cls(database_url=os.environ.get('ECHAT_DATABASE_URL', 'sqlite:///data/echat.db'),
            data_key=os.environ['ECHAT_DATA_KEY'], data_dir=Path(os.environ.get('ECHAT_DATA_DIR', 'data')),
            public_origin=origin, registration_token=os.environ.get('ECHAT_REGISTRATION_TOKEN', ''))