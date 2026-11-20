"""P-256 challenge signatures for identity; AES-GCM is SERVER encryption, not E2EE."""
from __future__ import annotations
import base64
import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64(text: str, max_length: int = 4096) -> bytes:
    if not isinstance(text, str) or len(text) > max_length:
        raise ValueError('Invalid encoded data')
    return base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)


def public_key(encoded: str):
    key = serialization.load_der_public_key(unb64(encoded))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError('A P-256 public key is required')
    canonical = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, canonical


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def account_id(der: bytes) -> str:
    return 'e_' + fingerprint(der)[:40]


def verify(der: bytes, transcript: str, signature: str):
    key = serialization.load_der_public_key(der)
    raw = unb64(signature, 512)
    # WebCrypto emits fixed-width r||s; Java/Python normally use ASN.1 DER.
    if len(raw) == 64:
        raw = utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
    key.verify(raw, transcript.encode('utf-8'), ec.ECDSA(hashes.SHA256()))


class Cipher:
    def __init__(self, encoded_key: str):
        key = unb64(encoded_key)
        if len(key) != 32:
            raise ValueError('ECHAT_DATA_KEY must encode exactly 32 random bytes')
        self.aes = AESGCM(key)

    def seal(self, plaintext: str, message_id: str) -> bytes:
        iv = os.urandom(12)
        return iv + self.aes.encrypt(iv, plaintext.encode('utf-8'), message_id.encode('ascii'))

    def open(self, ciphertext: bytes, message_id: str) -> str:
        return self.aes.decrypt(ciphertext[:12], ciphertext[12:], message_id.encode('ascii')).decode('utf-8')