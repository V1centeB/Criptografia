import re
from core.auth import Auth
from core.db_manager import DBManager
from core.pki_manager import setup_certificate_chain, issue_user_certificate
from core.security_logger import SecurityLogger
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen
from kivy.uix.textinput import TextInput

logger = SecurityLogger()

def show_popup(title, message):
    layout = BoxLayout(orientation='vertical')
    popup_label = Label(text=message)
    close_button = Button(text='Close', size_hint=(1, 0.25))

    layout.add_widget(popup_label)
    layout.add_widget(close_button)

    popup = Popup(title=title, content=layout, size_hint=(0.75, 0.5))
    close_button.bind(on_release=popup.dismiss)
    popup.open()

class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super(RegisterScreen, self).__init__(**kwargs)
        self.db_manager = DBManager()

        layout = BoxLayout(orientation='vertical', padding=10)

        self.username = TextInput(hint_text='Username', multiline=False)
        self.password = TextInput(hint_text='Password', password=True, multiline=False)
        self.email = TextInput(hint_text='Email', multiline=False)
        self.email_verification = TextInput(hint_text='Verify Email', multiline=False)

        register_btn = Button(text='Register')
        register_btn.bind(on_press=self.register_user)
        backlogin_btn = Button(text='Back to login')
        backlogin_btn.bind(on_press=self.go_to_login)

        layout.add_widget(self.username)
        layout.add_widget(self.password)
        layout.add_widget(self.email)
        layout.add_widget(self.email_verification)
        layout.add_widget(register_btn)
        layout.add_widget(backlogin_btn)

        self.add_widget(layout)

    def is_valid_email(self, email):
        email_regex = r'^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def is_valid_password(self, password):
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def register_user(self, instance):
        username = self.username.text
        password = self.password.text
        email = self.email.text
        email_verification = self.email_verification.text

        if email != email_verification:
            show_popup("Registration Error", "Email and verification do not match.")
            return

        if not self.is_valid_email(email):
            show_popup("Registration Error", "Invalid email format.")
            return

        if not self.is_valid_password(password):
            show_popup("Registration Error", "Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, and a special character.")
            return

        hashed_password = Auth.hash_password(password)

        if self.db_manager.add_user(username, hashed_password, email):
            try:
                # Preparar la cadena de certificados
                setup_certificate_chain()

                # Emitir el certificado del usuario
                issue_user_certificate(username)

                show_popup("Registration Success", "User registered successfully with certificate.")
                self.manager.current = 'login'
            except Exception as e:
                show_popup("Registration Error", f"Failed to generate certificate: {e}")
        else:
            show_popup("Registration Error", "User already exists.")

    def go_to_login(self, instance):
        self.manager.current = 'login'


from core.pki_manager import generate_user_cert

# Example usage in registration flow
def on_register_user(username, email):
    # Existing registration logic
    print(f"Registering user {username} with email {email}...")

    # Generate certificate for the user
    try:
        generate_user_cert(username, email)
        print(f"Certificate successfully generated for {username}.")
    except Exception as e:
        print(f"Failed to generate certificate for {username}: {str(e)}")
