from core.crypto_manager import generate_key, encrypt_data, decrypt_data
from core.db_manager import DBManager
from core.hmac_manager import generate_hmac, verify_hmac
from core.security_logger import SecurityLogger
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen
from kivy.uix.scrollview import ScrollView
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

class CredentialsScreen(Screen):
    def __init__(self, **kwargs):
        super(CredentialsScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10)

        self.service = TextInput(hint_text='Service Name', multiline=False)
        self.service_user = TextInput(hint_text='Service Username', multiline=False)
        self.service_password = TextInput(hint_text='Service Password', multiline=False)

        save_btn = Button(text='Save Credentials')
        save_btn.bind(on_press=self.save_credentials)

        view_btn = Button(text='View Credentials')
        view_btn.bind(on_press=self.view_credentials)

        layout.add_widget(self.service)
        layout.add_widget(self.service_user)
        layout.add_widget(self.service_password)
        layout.add_widget(save_btn)
        layout.add_widget(view_btn)
        self.add_widget(layout)

    def save_credentials(self, instance):
        service = self.service.text
        service_user = self.service_user.text
        service_password = self.service_password.text
        username = self.manager.get_screen('login').username.text
        user_password = self.manager.get_screen('login').password.text

        if service and service_user and service_password:
            salt = f"{username}{service_user}".encode('utf-8')

            key = generate_key(user_password, salt)

            # Cifrado
            encrypted_user = encrypt_data(service_user, key)
            encrypted_password = encrypt_data(service_password, key)

            # Generar HMAC
            hmac_user = generate_hmac(encrypted_user, salt)
            hmac_password = generate_hmac(encrypted_password, salt)

            # Loggear datos cifrados y HMAC
            logger.log_encrypted_data("Encrypted username", encrypted_user)
            logger.log_encrypted_data("Encrypted password", encrypted_password)
            logger.log_hmac_generation(hmac_user)
            logger.log_hmac_generation(hmac_password)
            logger.log_separator()

            # Guardar en la base de datos
            db_manager = DBManager()
            db_manager.store_credentials(username, service, encrypted_user, encrypted_password, hmac_user,
                                         hmac_password, salt.decode('utf-8'))

            show_popup("Success", "Credentials saved successfully.")
        else:
            show_popup("Error", "Please fill out all fields.")

    def view_credentials(self, instance):
        username = self.manager.get_screen('login').username.text
        user_password = self.manager.get_screen('login').password.text  # Contraseña del usuario
        db_manager = DBManager()
        credentials = db_manager.get_user_credentials(username)

        if credentials:
            layout = GridLayout(cols=1, padding=10, spacing=10, size_hint_y=None)
            layout.bind(minimum_height=layout.setter('height'))

            for credential in credentials:
                service = credential[1]
                encrypted_user = credential[2]
                encrypted_password = credential[3]
                hmac_user = credential[4]
                hmac_password = credential[5]
                salt = credential[6].encode('utf-8')

                # Generar la clave usando la contraseña del usuario y el salt
                key = generate_key(user_password, salt)

                credential_layout = BoxLayout(orientation='horizontal', spacing=10, size_hint_y=None, height=40)

                user_label = Label(text="****", size_hint_x=0.3, halign="left", valign="middle")
                password_label = Label(text="****", size_hint_x=0.3, halign="left", valign="middle")

                toggle_button = Button(text="Show", size_hint_x=0.2, height=30)
                toggle_button.background_color = (0.2, 0.6, 0.8, 1)
                toggle_button.color = (1, 1, 1, 1)

                toggle_button.bind(on_press=lambda btn, enc_user=encrypted_user, enc_pass=encrypted_password,
                                                   h_user=hmac_user, h_pass=hmac_password, u_label=user_label,
                                                   p_label=password_label,
                                                   key=key, salt=salt: self.toggle_visibility(enc_user, enc_pass,
                                                                                              h_user, h_pass, u_label,
                                                                                              p_label, key, salt, btn))

                credential_layout.add_widget(
                    Label(text=f"Service: {service}", size_hint_x=0.3, halign="left", valign="middle"))
                credential_layout.add_widget(user_label)
                credential_layout.add_widget(password_label)
                credential_layout.add_widget(toggle_button)

                layout.add_widget(credential_layout)

            scroll_view = ScrollView(size_hint=(1, None), size=(400, 300))
            scroll_view.add_widget(layout)

            popup_layout = BoxLayout(orientation='vertical')
            popup_layout.add_widget(scroll_view)

            close_button = Button(text='Close', size_hint=(1, 0.2))
            close_button.bind(on_release=lambda x: popup.dismiss())
            popup_layout.add_widget(close_button)

            popup = Popup(title="Stored Credentials", content=popup_layout, size_hint=(0.9, 0.9))
            popup.open()
        else:
            show_popup("No Credentials", "No credentials found for this user.")

    def toggle_visibility(self, encrypted_user, encrypted_password, hmac_user, hmac_password, user_label, password_label, key, salt, button):
        if user_label.text == "****" and password_label.text == "****":
            user_verification = verify_hmac(hmac_user, encrypted_user, salt)
            password_verification = verify_hmac(hmac_password, encrypted_password, salt)

            logger.log_hmac_verification("Username", user_verification)
            logger.log_hmac_verification("Password", password_verification)
            logger.log_separator()

            if user_verification and password_verification:

                logger.log_encrypted_data("Username", encrypted_user)
                logger.log_encrypted_data("Password", encrypted_password)
                logger.log_separator()

                decrypted_user = decrypt_data(encrypted_user, key)
                decrypted_password = decrypt_data(encrypted_password, key)

                logger.log_decrypted_data("Decrypted username", decrypted_user)
                logger.log_decrypted_data("Decrypted password", decrypted_password)
                logger.log_separator()
                logger.log_key_salt(key, salt)
                logger.log_separator()

                user_label.text = decrypted_user
                password_label.text = decrypted_password
                button.text = "Hide"
            else:
                show_popup("Error", "Data integrity check failed. HMAC verification failed.")
        else:
            user_label.text = "****"
            password_label.text = "****"
            button.text = "Show"
