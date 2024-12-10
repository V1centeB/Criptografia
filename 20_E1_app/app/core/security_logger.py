import logging

class SecurityLogger:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        self.logger = logging.getLogger("SecurityLogger")

    def log_encrypted_data(self, data_type, encrypted_data):
        self.logger.info(f"{data_type} cifrado: {encrypted_data}")

    def log_decrypted_data(self, data_type, decrypted_data):
        self.logger.info(f"{data_type} descifrado: {decrypted_data}")

    def log_separator(self):
        self.logger.info("-" * 30)

    def log_key_salt(self, key, salt):
        self.logger.info(f"[Key used for decryption] {key}")
        self.logger.info(f"[Salt used for decryption] {salt}")

    def log_hmac_generation(self, hmac_data):
        self.logger.info(f"HMAC generado: {hmac_data}")

    def log_hmac_verification(self, data_type, result):
        status = "exitosa" if result else "fallida"
        self.logger.info(f"Verificación HMAC para {data_type}: {status}")

    def log_ca_creation(self, ca_name):
        self.logger.info(f"CA '{ca_name}' creada con éxito.")

    def log_certificate_issued(self, username):
        self.logger.info(f"Certificado emitido para el usuario '{username}'.")

    def log_certificate_verified(self, username, result):
        status = "válido" if result else "inválido"
        self.logger.info(f"Certificado del usuario '{username}' es {status}.")

    def log_pki_error(self, operation, error):
        self.logger.error(f"Error durante '{operation}': {error}")
