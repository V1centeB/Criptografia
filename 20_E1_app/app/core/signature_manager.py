from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_key_pair():
    """
    Genera un par de claves RSA.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(data: bytes, private_key):
    """
    Firma digitalmente los datos usando la clave privada.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key):
    """
    Verifica la firma digital de los datos usando la clave pública.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Error al verificar la firma: {e}")
        return False


def save_key_to_file(key, filepath: str, is_private: bool = True):
    """
    Guarda una clave (privada o pública) en un archivo.
    """
    if is_private:
        with open(filepath, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    else:
        with open(filepath, "wb") as f:
            f.write(
                key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )


def load_key_from_file(filepath: str, is_private: bool = True):
    """
    Carga una clave (privada o pública) desde un archivo.
    """
    with open(filepath, "rb") as f:
        key_data = f.read()
        if is_private:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        else:
            return serialization.load_pem_public_key(key_data, backend=default_backend())
