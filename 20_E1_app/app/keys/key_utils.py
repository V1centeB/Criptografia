import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def load_public_key():

    with open("keys/clave_publica.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read(), backend=default_backend())
    return public_key


def load_private_key():

    with open("keys/clave_privada_encriptada.pem", "rb") as private_file:
        encrypted_data = private_file.read()

    # Extraer salt, IV y datos cifrados
    salt = encrypted_data[:16]
    iv = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]

    # Regenerar clave de cifrado
    clave_cifrado = generate_deterministic_key(42, salt)

    # Descifrar la clave privada
    cipher = Cipher(algorithms.AES(clave_cifrado), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    private_key_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    # Cargar la clave privada descifrada
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

def generate_deterministic_key(seed: int, salt: bytes) -> bytes:
    random.seed(seed)
    reproducible_number = random.randint(0, 1_000_000)
    seed_str = str(reproducible_number)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(seed_str.encode('utf-8'))

