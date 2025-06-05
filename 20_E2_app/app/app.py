from kivy.app import App

from core.db_manager import DBManager
from core.pki_manager import initialize_pki_structure, initialize_pki
from interface.screen_manager import MyScreenManager
from keys.creator_keys import generate_keys

class MyApp(App):
    def build(self):
        generate_keys()
        initialize_pki_structure()
        initialize_pki()
        db_manager = DBManager()
        db_manager.setup_database()
        sm = MyScreenManager()

        return sm

if __name__ == '__main__':
    MyApp().run()