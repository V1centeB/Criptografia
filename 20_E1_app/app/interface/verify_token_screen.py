from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from core.email_manager import verify_token

def show_popup(title, message):
    layout = BoxLayout(orientation='vertical')
    popup_label = Label(text=message)
    close_button = Button(text='Close', size_hint=(1, 0.25))

    layout.add_widget(popup_label)
    layout.add_widget(close_button)

    popup = Popup(title=title, content=layout, size_hint=(0.75, 0.5))
    close_button.bind(on_release=popup.dismiss)
    popup.open()

class VerifyTokenScreen(Screen):
    def __init__(self, **kwargs):
        super(VerifyTokenScreen, self).__init__(**kwargs)
        self.full_token = None  
        
        layout = BoxLayout(orientation='vertical', padding=10)
        self.token_input = TextInput(hint_text='Enter verification code', multiline=False)
        
        verify_btn = Button(text='Verify')
        verify_btn.bind(on_press=self.verify_user_token) 

        layout.add_widget(self.token_input)
        layout.add_widget(verify_btn)
        self.add_widget(layout)

    def set_token(self, token):
        self.full_token = token

    def verify_user_token(self, instance):
        if self.full_token is None:
            show_popup('Error', 'No token has been set for verification.')
            return

        entered_token = self.token_input.text.strip()

        if not entered_token:
            show_popup('Error', 'Please enter the code.')
            return

        if verify_token(self.full_token, max_age=60) and self.full_token.split(':')[0] == entered_token:
            show_popup('Success', 'Authentication completed.')
            self.manager.current = 'credentials'
        else:
            show_popup('Error', 'Incorrect or expired code.')
