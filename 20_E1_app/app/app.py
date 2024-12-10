from kivy.app import App

from core.db_manager import DBManager
from interface.screen_manager import MyScreenManager
from keys.creator_keys import generate_keys

class MyApp(App):
    def build(self):
        generate_keys()
        db_manager = DBManager()
        db_manager.setup_database()
        sm = MyScreenManager()

        return sm

if __name__ == '__main__':
    MyApp().run()

# Import PKI Manager for certificate handling
from core.pki_manager import generate_user_cert

def register_user_with_cert(username, email):
    try:
        # Call the PKI manager to generate a certificate for the user
        generate_user_cert(username, email)
        print(f"User {username} registered with certificate generated.")
    except Exception as e:
        print(f"Error generating certificate for {username}: {str(e)}")
