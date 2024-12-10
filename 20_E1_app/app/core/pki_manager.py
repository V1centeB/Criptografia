import os
import subprocess
from core.security_logger import SecurityLogger

logger = SecurityLogger()

# Rutas de certificados y claves
AC1_DIR = "AC1"
AC2_DIR = "AC2"
USER_DIR = "A"

def setup_certificate_chain():
    """
    Prepara la cadena de certificados concatenando AC1 y AC2.
    """
    try:
        ac1_cert_path = os.path.join(AC1_DIR, "ac1cert.pem")
        ac2_cert_path = os.path.join(AC2_DIR, "ac2cert.pem")
        certs_chain_path = os.path.join(USER_DIR, "certs.pem")

        with open(certs_chain_path, "wb") as certs_file:
            for cert_path in [ac1_cert_path, ac2_cert_path]:
                with open(cert_path, "rb") as cert_file:
                    certs_file.write(cert_file.read())

        logger.logger.info("Cadena de certificados preparada.")
    except Exception as e:
        logger.log_pki_error("Preparación de la cadena de certificados", e)
        raise e


def issue_user_certificate(username):
    """
    Genera un certificado para el usuario firmado por AC2.
    """
    try:
        # Rutas para claves y certificados de usuario
        user_key_path = os.path.join(USER_DIR, f"{username}_key.pem")
        user_cert_path = os.path.join(USER_DIR, f"{username}_cert.pem")
        cert_request_path = os.path.join(USER_DIR, f"{username}_req.pem")
        ac2_config_path = os.path.join(AC2_DIR, "AC2-38114.cnf")

        # Generar clave privada y solicitud de certificado (CSR) para el usuario
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", user_key_path, "-out", cert_request_path,
            "-subj", f"/C=ES/O=Users/OU=Department/CN={username}"
        ], check=True)

        logger.logger.info(f"Solicitud de certificado generada para {username}.")

        # Firmar el CSR con AC2 para generar el certificado del usuario
        subprocess.run([
            "openssl", "ca", "-config", ac2_config_path,
            "-in", cert_request_path, "-out", user_cert_path, "-batch"
        ], check=True)

        logger.logger.info(f"Certificado emitido para {username} y firmado por AC2.")
    except subprocess.CalledProcessError as e:
        logger.log_pki_error(f"Error al emitir certificado para '{username}'", e)
        raise e
    except Exception as e:
        logger.log_pki_error(f"Error general al emitir certificado para '{username}'", e)
        raise e


def verify_user_certificate(username):
    """
    Verifica el certificado de un usuario contra la jerarquía AC2 -> AC1.
    """
    try:
        user_cert_path = os.path.join(USER_DIR, f"{username}_cert.pem")
        certs_chain_path = os.path.join(USER_DIR, "certs.pem")

        # Verificar el certificado del usuario contra la cadena de confianza
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", certs_chain_path, user_cert_path],
            capture_output=True,
            text=True
        )

        if "OK" in result.stdout:
            logger.log_certificate_verified(username, True)
            return True
        else:
            logger.log_certificate_verified(username, False)
            return False
    except Exception as e:
        logger.log_pki_error(f"Verificación de certificado para {username}", e)
        return False


def authenticate_user(username, password, db_manager):
    """
    Autentica a un usuario verificando sus credenciales y su certificado.
    """
    if not db_manager.verify_credentials(username, password):
        logger.logger.info("Credenciales incorrectas.")
        return False

    if not verify_user_certificate(username):
        logger.logger.info("El certificado del usuario no es válido.")
        return False

    logger.logger.info("Usuario autenticado con éxito.")
    return True


import os
import subprocess

# Base directory for app structure
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_user_cert(username, email):
    user_dir = os.path.join(BASE_DIR, "..", "A")
    ac2_dir = os.path.join(BASE_DIR, "..", "AC2")

    # Paths for user keys and certificates
    user_key = os.path.join(user_dir, f"{username}key.pem")
    user_req = os.path.join(user_dir, f"{username}req.pem")
    user_cert = os.path.join(user_dir, f"{username}cert.pem")

    # Generate RSA key and certificate request
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:1024", "-days", "360", "-sha1",
        "-keyout", user_key, "-out", user_req,
        "-subj", f"/C=ES/ST=MADRID/O=UC3M/CN={username}/emailAddress={email}"
    ], check=True)

    # Move request to AC2 directory
    subprocess.run(["mv", user_req, os.path.join(ac2_dir, "solicitudes")], check=True)

    # Generate certificate using AC2
    subprocess.run([
        "openssl", "ca", "-in", os.path.join(ac2_dir, "solicitudes", f"{username}req.pem"),
        "-notext", "-config", os.path.join(ac2_dir, "AC2-38114.cnf"),
        "-out", os.path.join(ac2_dir, "nuevoscerts", f"{username}cert.pem")
    ], check=True)

    # Move certificate back to user directory
    subprocess.run(["mv", os.path.join(ac2_dir, "nuevoscerts", f"{username}cert.pem"), user_cert], check=True)
    print(f"Certificate for {username} generated successfully.")

