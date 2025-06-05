import os
from datetime import datetime, timedelta
import cryptography.x509 as x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import NameOID
from core.security_logger import SecurityLogger  # Importar la clase SecurityLogger

logger = SecurityLogger()

def initialize_pki_structure():
    directories = {
        "AC1": ["solicitudes", "crls", "nuevoscerts", "privado"],
        "AC2": ["solicitudes", "crls", "nuevoscerts", "privado"],
        "A": []
    }

    for base_dir, subdirs in directories.items():
        os.makedirs(base_dir, exist_ok=True)
        for subdir in subdirs:
            os.makedirs(f"{base_dir}/{subdir}", exist_ok=True)

        if base_dir in ["AC1", "AC2"]:
            with open(f"{base_dir}/serial", "w") as f:
                f.write("01")
            open(f"{base_dir}/index.txt", "w").close()
    logger.logger.info("Estructura PKI inicializada con éxito.")

def initialize_pki():
    if not os.path.exists("AC1/nuevoscerts/certificate.pem"):
        create_ca_root()
    if not os.path.exists("AC2/nuevoscerts/certificate.pem"):
        create_ca_subordinate()

def create_ca_root():
    try:
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

        with open("AC1/privado/private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("AC1/nuevoscerts/certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        logger.log_ca_creation("AC1")
    except Exception as e:
        logger.log_pki_error("Creación de CA raíz", e)

def create_ca_subordinate():
    try:
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
        with open("AC1/privado/private_key.pem", "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), None)
        with open("AC1/nuevoscerts/certificate.pem", "rb") as f:
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

        with open("AC2/privado/private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("AC2/nuevoscerts/certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        logger.log_ca_creation("AC2")
    except Exception as e:
        logger.log_pki_error("Creación de CA subordinada", e)

def issue_user_certificate(username):
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"User"),
            x509.NameAttribute(NameOID.COMMON_NAME, username)
        ])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
            private_key, hashes.SHA256()
        )

        with open("AC2/privado/private_key.pem", "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), None)
        with open("AC2/nuevoscerts/certificate.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        certificate = x509.CertificateBuilder().subject_name(
            csr.subject).issuer_name(
            ca_cert.subject).public_key(
            public_key).serial_number(
            x509.random_serial_number()).not_valid_before(
            datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(ca_private_key, hashes.SHA256())

        user_dir = f"A/{username}"
        os.makedirs(user_dir, exist_ok=True)
        with open(f"{user_dir}/{username}_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(f"{user_dir}/{username}_certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        logger.log_certificate_issued(username)
    except Exception as e:
        logger.log_pki_error(f"Emisión del certificado para '{username}'", e)

def verify_user_certificate(username):
    try:
        with open(f"A/{username}/{username}_certificate.pem", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())
        with open("AC2/nuevoscerts/certificate.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )
        logger.log_certificate_verified(username, True)
        return True
    except Exception as e:
        logger.log_certificate_verified(username, False)
        logger.log_pki_error("Verificación de certificado", e)
        return False
