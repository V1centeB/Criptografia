import sqlite3
from core.config import DB_FILE

class DBManager:
    def __init__(self, db_name=DB_FILE):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

    def setup_database(self):
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            email TEXT
        )
        ''')
        self.conn.commit()

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            username TEXT,
            service TEXT,
            service_user TEXT,
            encrypted_password TEXT,
            hmac_user TEXT,
            hmac_password TEXT,
            salt TEXT,
            PRIMARY KEY (username, service),
            FOREIGN KEY (username) REFERENCES users(username)
        )
        ''')
        self.conn.commit()

    def add_user(self, username, password, email):
        try:
            self.cursor.execute('''
            INSERT INTO users (username, password, email)
            VALUES (?, ?, ?)
            ''', (username, password, email))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username):
        self.cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        return self.cursor.fetchone()

    def get_user_credentials(self, username):
        self.cursor.execute('SELECT * FROM credentials WHERE username=?', (username,))
        return self.cursor.fetchall()
    
    def store_credentials(self, username, service, service_user, encrypted_password, hmac_user, hmac_password, salt):
        self.cursor.execute('''
        INSERT INTO credentials (username, service, service_user, encrypted_password, hmac_user, hmac_password, salt)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(username, service) DO UPDATE 
        SET service_user=excluded.service_user, encrypted_password=excluded.encrypted_password, hmac_user=excluded.hmac_user, hmac_password=excluded.hmac_password, salt=excluded.salt
        ''', (username, service, service_user, encrypted_password, hmac_user, hmac_password, salt))
        self.conn.commit()