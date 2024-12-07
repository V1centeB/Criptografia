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
