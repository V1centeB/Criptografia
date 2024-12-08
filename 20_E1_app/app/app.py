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