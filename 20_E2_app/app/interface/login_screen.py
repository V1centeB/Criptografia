from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.screenmanager import Screen
from kivy.uix.popup import Popup
from core.db_manager import DBManager
from core.email_manager import send_verification_token, generate_temporary_token
from core.auth import Auth
from core.pki_manager import verify_user_certificate



def show_popup(title, message):
    layout = BoxLayout(orientation='vertical')
    popup_label = Label(text=message)
    close_button = Button(text='Close', size_hint=(1, 0.25))

    layout.add_widget(popup_label)
    layout.add_widget(close_button)

    popup = Popup(title=title, content=layout, size_hint=(0.75, 0.5))
    close_button.bind(on_release=popup.dismiss)
    popup.open()

class LoginScreen(Screen):
    current_user = None
    user_password = None

    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        self.db_manager = DBManager()
        
        layout = BoxLayout(orientation='vertical', padding=10)

        self.username = TextInput(hint_text='Username', multiline=False)
        self.password = TextInput(hint_text='Password', password=True, multiline=False)

        login_btn = Button(text='Log in')
        login_btn.bind(on_press=self.verify_login)

        register_btn = Button(text='Register new user')
        register_btn.bind(on_press=self.go_to_register)

        layout.add_widget(self.username)
        layout.add_widget(self.password)
        layout.add_widget(login_btn)
        layout.add_widget(register_btn)
        self.add_widget(layout)

    def verify_login(self, instance):
        username = self.username.text
        password = self.password.text
        user = self.db_manager.get_user(username)

        if user:
            stored_password = user[1]
            if Auth.check_password(password, stored_password):
                try:
                    if verify_user_certificate(username):
                        LoginScreen.current_user = username
                        LoginScreen.user_password = password
                        email = user[2]

                        token = send_verification_token(email)
                        if token:
                            verify_screen = self.manager.get_screen('verify')
                            verify_screen.set_token(token)
                            self.manager.current = 'verify'
                        else:
                            show_popup("Error", "Failed to send verification token.")
                    else:
                        show_popup("Error", "User certificate validation failed.")
                except Exception as e:
                    show_popup("Error", f"Failed to verify user certificate: {e}")
            else:
                show_popup('Error', 'Incorrect username or password')
        else:
            show_popup('Error', 'User not found')

    def clear_login_fields(self):
        self.username.text = ""
        self.password.text = ""

    def go_to_register(self, instance):
        self.manager.current = 'register'
