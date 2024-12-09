import hashlib
import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_hmac_key(key: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(key.encode())

def generate_hmac(data, salt=None):
    key = generate_hmac_key(data, salt)
    data_bytes = data.encode('utf-8')
    hmac_obj = hmac.new(key, data_bytes, hashlib.sha256)
    return hmac_obj.hexdigest()

def verify_hmac(stored_hmac, data, salt=None):
    calculated_hmac = generate_hmac(data, salt)
    return hmac.compare_digest(stored_hmac, calculated_hmac)
