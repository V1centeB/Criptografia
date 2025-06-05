from kivy.uix.screenmanager import ScreenManager
from interface.login_screen import LoginScreen
from interface.register_screen import RegisterScreen
from interface.verify_token_screen import VerifyTokenScreen
from interface.credentials_screen import CredentialsScreen

class MyScreenManager(ScreenManager):
    def __init__(self, **kwargs):
        super(MyScreenManager, self).__init__(**kwargs)
        
        self.add_widget(LoginScreen(name='login'))
        self.add_widget(RegisterScreen(name='register'))
        self.add_widget(VerifyTokenScreen(name='verify'))
        self.add_widget(CredentialsScreen(name='credentials'))

