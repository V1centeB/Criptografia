import bcrypt

class Auth:
    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')  

    @staticmethod
    def check_password(provided_password, stored_password):
        try:
            stored_password_bytes = stored_password.encode('utf-8')

            return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_bytes)

        except (ValueError, TypeError) as e:
            print(f"Password verification error: {e}")
            return False
