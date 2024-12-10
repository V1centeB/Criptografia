import os
from datetime import datetime, timedelta

import cryptography.x509 as x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import NameOID


def initialize_pki_structure():
    """
    Crea la estructura de directorios necesaria para la PKI.
    """
    directories = ["keys/AC1", "keys/AC2", "keys/users"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def initialize_pki():
    if not os.path.exists("keys/AC1/certificate.pem"):
        create_ca_root()
    if not os.path.exists("keys/AC2/certificate.pem"):
        create_ca_subordinate()


def create_ca_root():
    """
    Genera la CA raíz (AC1) y guarda su clave privada y certificado.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CA Root"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"AC1")
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject).issuer_name(
        issuer).public_key(
        public_key).serial_number(
        x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())

    # Guardar claves y certificado
    with open("keys/AC1/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("keys/AC1/certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("CA raíz (AC1) creada con éxito.")


def create_ca_subordinate():
    """
    Genera la CA subordinada (AC2) y la firma con la CA raíz (AC1).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CA Subordinate"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"AC2")
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256()
    )

    with open("keys/AC1/private_key.pem", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), None)
    with open("keys/AC1/certificate.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    certificate = x509.CertificateBuilder().subject_name(
        csr.subject).issuer_name(
        ca_cert.subject).public_key(
        public_key).serial_number(
        x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).sign(ca_private_key, hashes.SHA256())

    # Guardar claves y certificado
    with open("keys/AC2/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("keys/AC2/certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("CA subordinada (AC2) creada con éxito.")


def issue_user_certificate(username):
    """
    Genera un certificado para el usuario firmado por la CA subordinada (AC2).
    """
    # 1. Generar claves para el usuario
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # 2. Crear la solicitud de certificado (CSR) para el usuario
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"User"),
        x509.NameAttribute(NameOID.COMMON_NAME, username)
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256()
    )

    # 3. Cargar la clave privada y certificado de la CA subordinada (AC2)
    with open("keys/AC2/private_key.pem", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), None)
    with open("keys/AC2/certificate.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # 4. Emitir el certificado para el usuario
    certificate = x509.CertificateBuilder().subject_name(
        csr.subject).issuer_name(
        ca_cert.subject).public_key(
        public_key).serial_number(
        x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Validez de 1 año
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_private_key, hashes.SHA256())

    # 5. Guardar claves y certificado del usuario
    user_dir = f"keys/users/{username}"
    os.makedirs(user_dir, exist_ok=True)

    with open(f"{user_dir}/{username}_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"{user_dir}/{username}_certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"Certificado emitido y almacenado para el usuario '{username}'.")

def verify_user_certificate(username):
    """
    Verifica el certificado de un usuario contra la CA subordinada (AC2).
    """
    try:
        # Cargar el certificado del usuario
        with open(f"keys/users/{username}/{username}_certificate.pem", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        # Cargar el certificado de la CA subordinada (AC2)
        with open("keys/AC2/certificate.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Verificar que el certificado del usuario esté firmado por AC2
        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )

        print(f"El certificado del usuario '{username}' es válido.")
        return True
    except Exception as e:
        print(f"Error al verificar el certificado del usuario '{username}': {e}")
        return False

def authenticate_user(username, password, db_manager):
    """
    Autentica a un usuario verificando sus credenciales y su certificado.
    """
    if not db_manager.verify_credentials(username, password):
        print("Credenciales incorrectas.")
        return False

    if not verify_user_certificate(username):
        print("El certificado del usuario no es válido.")
        return False

    print("Usuario autenticado con éxito.")
    return True


