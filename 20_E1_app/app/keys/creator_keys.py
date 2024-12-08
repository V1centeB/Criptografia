import os
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_deterministic_key(seed: int) -> bytes:
    salt = b"fixed_salt_value"
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

def generate_keys():

    os.makedirs("keys", exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    with open("keys/clave_publica.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    clave_cifrado = generate_deterministic_key(42)

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(clave_cifrado), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_private_key = encryptor.update(private_key_bytes) + encryptor.finalize()

    with open("keys/clave_privada_encriptada.pem", "wb") as private_file:
        private_file.write(iv + encryptor.tag + encrypted_private_key)

    #todo Mostrar mensaje de éxito a través del Logger
    print("Claves generadas y guardadas con éxito en la carpeta 'keys'.")

if __name__ == "__main__":
    generate_keys()
