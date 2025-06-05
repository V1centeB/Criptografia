import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from keys.key_utils import load_private_key

def generate_key(salt: bytes) -> bytes:
    private_key = load_private_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la clave generada
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    derived_key = kdf.derive(private_key_bytes)

    return derived_key


def encrypt_data(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


def decrypt_data(ciphertext: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext)

    iv = data[:16]  
    actual_ciphertext = data[16:]  

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()
