import hmac
import hashlib
import secrets

def generate_hmac_key():
    return secrets.token_bytes(32)

def generate_hmac(data):
    data_bytes = data.encode('utf-8')
    hmac_obj = hmac.new(b"", data_bytes, hashlib.sha256)
    return hmac_obj.hexdigest()

def verify_hmac(stored_hmac, data):
    calculated_hmac = generate_hmac(data)
    return hmac.compare_digest(stored_hmac, calculated_hmac)
