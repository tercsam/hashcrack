import hashlib
import itertools
import string
import threading
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup

class HashCrackerApp(App):
    def build(self):
        self.title = "Hash Cracker"
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.hash_input = TextInput(hint_text='Enter the Hash', multiline=False)
        self.layout.add_widget(self.hash_input)

        self.result_label = Label(text='Result will be displayed here')
        self.layout.add_widget(self.result_label)

        self.attack_type = 'dictionary'
        self.max_length = 4

        dict_button = Button(text='1. Dictionary Attack', size_hint_y=None, height=50)
        dict_button.bind(on_press=self.select_dictionary_attack)
        self.layout.add_widget(dict_button)

        brute_button = Button(text='2. Brute Force Attack', size_hint_y=None, height=50)
        brute_button.bind(on_press=self.select_brute_force_attack)
        self.layout.add_widget(brute_button)

        start_button = Button(text='Start Attack', size_hint_y=None, height=50)
        start_button.bind(on_press=self.start_attack)
        self.layout.add_widget(start_button)

        return self.layout

    def select_dictionary_attack(self, instance):
        self.attack_type = 'dictionary'
        self.show_file_chooser()

    def select_brute_force_attack(self, instance):
        self.attack_type = 'brute_force'
        self.show_brute_force_options()

    def show_file_chooser(self):
        self.file_chooser = FileChooserListView(path='/', filters=['*.txt'], size_hint=(0.9, 0.9))
        select_button = Button(text="Select", size_hint_y=None, height=50)
        select_button.bind(on_press=self.on_file_selected)

        file_popup_layout = BoxLayout(orientation='vertical')
        file_popup_layout.add_widget(self.file_chooser)
        file_popup_layout.add_widget(select_button)

        self.file_popup = Popup(title="Select Dictionary File", content=file_popup_layout, size_hint=(0.9, 0.9))
        self.file_popup.open()

    def on_file_selected(self, instance):
        self.dictionary_file = self.file_chooser.selection[0]
        self.file_popup.dismiss()
        self.result_label.text = f"Selected file: {self.dictionary_file}"

    def show_brute_force_options(self):
        brute_force_layout = BoxLayout(orientation='vertical')
        self.length_input = TextInput(hint_text="Max password length (default is 4)", multiline=False)
        brute_force_layout.add_widget(self.length_input)

        start_button = Button(text="Start Brute Force", size_hint_y=None, height=50)
        start_button.bind(on_press=self.on_brute_force_selected)
        brute_force_layout.add_widget(start_button)

        self.brute_force_popup = Popup(title="Brute Force Options", content=brute_force_layout, size_hint=(0.8, 0.5))
        self.brute_force_popup.open()

    def on_brute_force_selected(self, instance):
        try:
            self.max_length = int(self.length_input.text) if self.length_input.text else 4
            self.brute_force_popup.dismiss()
            self.result_label.text = f"Max length set to {self.max_length}"
        except ValueError:
            self.result_label.text = "Invalid input for max length"

    def start_attack(self, instance):
        hash_to_crack = self.hash_input.text
        hash_type = self.detect_hash_type(hash_to_crack)
        if not hash_type:
            self.result_label.text = "[-] Unknown hash type."
            return

        self.result_label.text = f"[+] Detected hash type: {hash_type}"

        if self.attack_type == 'dictionary':
            self.dictionary_attack(hash_to_crack, hash_type, self.dictionary_file)
        elif self.attack_type == 'brute_force':
            self.brute_force_attack(hash_to_crack, hash_type, self.max_length)

    def hash_password(self, password, hash_type='md5'):
        try:
            hash_func = hashlib.new(hash_type)
        except ValueError:
            self.result_label.text = f"[-] Hash type {hash_type} not supported."
            return None
        hash_func.update(password.encode('utf-8'))
        return hash_func.hexdigest()

    def dictionary_attack(self, hash_to_crack, hash_type, dictionary_file):
        try:
            with open(dictionary_file, 'r') as f:
                for line in f:
                    word = line.strip()
                    if self.hash_password(word, hash_type) == hash_to_crack:
                        self.result_label.text = f"[+] Password found: {word}"
                        return word
        except FileNotFoundError:
            self.result_label.text = f"[-] Dictionary file {dictionary_file} not found."
        self.result_label.text = "[-] Password not found in dictionary."
        return None

    def brute_force_worker(self, hash_to_crack, hash_type, chars, length, found):
        for guess in itertools.product(chars, repeat=length):
            if found.is_set():
                break
            guess = ''.join(guess)
            if self.hash_password(guess, hash_type) == hash_to_crack:
                self.result_label.text = f"[+] Password found: {guess}"
                found.set()
                return guess

    def brute_force_attack(self, hash_to_crack, hash_type, max_length=4, num_threads=4):
        characters = string.ascii_letters + string.digits + string.punctuation
        found = threading.Event()

        for length in range(1, max_length + 1):
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=self.brute_force_worker,
                                     args=(hash_to_crack, hash_type, characters, length, found))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            if found.is_set():
                break
        if not found.is_set():
            self.result_label.text = "[-] Password not found with brute force."
        return None

    def detect_hash_type(self, hash_to_crack):
        hash_length = len(hash_to_crack)
        if hash_length == 32:
            return 'md5'
        elif hash_length == 40:
            return 'sha1'
        elif hash_length == 64:
            return 'sha256'
        elif hash_length == 128:
            return 'sha512'
        else:
            return None

if __name__ == '__main__':
    HashCrackerApp().run()
