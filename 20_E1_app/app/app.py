from kivy.app import App

from core.db_manager import DBManager
from interface.screen_manager import MyScreenManager


class MyApp(App):
    def build(self):
        db_manager = DBManager()
        db_manager.setup_database()
        sm = MyScreenManager()
        return sm

if __name__ == '__main__':
    MyApp().run()