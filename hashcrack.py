import hashlib
import itertools
import string
import threading
import multiprocessing
import os
from kivy.lang import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.metrics import dp
from kivymd.app import MDApp
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.boxlayout import MDBoxLayout
import bcrypt
import argon2
import re

KV = '''
BoxLayout:
    orientation: 'vertical'
    padding: dp(20)
    spacing: dp(20)

    MDLabel:
        text: 'Hash Cracker'
        font_style: 'H3'
        halign: 'center'

    MDTextField:
        id: hash_input
        hint_text: 'Enter the Hash'
        mode: 'rectangle'

    MDLabel:
        id: result_label
        text: 'Result will be displayed here'
        halign: 'center'

    MDRaisedButton:
        text: '1. Dictionary Attack'
        size_hint_y: None
        height: dp(50)
        on_release: app.select_dictionary_attack()

    MDRaisedButton:
        text: '2. Brute Force Attack'
        size_hint_y: None
        height: dp(50)
        on_release: app.select_brute_force_attack()

    MDRaisedButton:
        text: 'Start Attack'
        size_hint_y: None
        height: dp(50)
        md_bg_color: app.theme_cls.primary_color
        on_release: app.start_attack()
'''

def brute_force_worker(hash_to_crack, hash_type, chars, length, found, result):
    for guess in itertools.product(chars, repeat=length):
        if found.is_set():
            break
        guess = ''.join(guess)
        if hash_type == 'bcrypt':
            if bcrypt.checkpw(guess.encode('utf-8'), hash_to_crack.encode('utf-8')):
                found.set()
                result.put(guess)
                return guess
        elif hash_type == 'argon2':
            # Argon2 is tricky; requires correct implementation or library support
            pass
        elif hash_type == 'scrypt':
            # scrypt is tricky; requires correct implementation or library support
            pass
        else:
            # Other hash types
            if hashlib.new(hash_type, guess.encode('utf-8')).hexdigest() == hash_to_crack:
                found.set()
                result.put(guess)
                return guess

def brute_force_attack(hash_to_crack, hash_type, max_length=4):
    characters = string.ascii_letters + string.digits + string.punctuation
    found = multiprocessing.Event()
    result = multiprocessing.Queue()

    for length in range(1, max_length + 1):
        if found.is_set():
            break
        processes = []
        for _ in range(multiprocessing.cpu_count()):
            p = multiprocessing.Process(target=brute_force_worker, args=(hash_to_crack, hash_type, characters, length, found, result))
            processes.append(p)
            p.start()

        for p in processes:
            p.join()

        if found.is_set():
            return result.get()

    return None

class HashCracker:
    def detect_hash_type(self, hash_to_crack):
        # Vérifiez que l'entrée est une chaîne de caractères
        if not isinstance(hash_to_crack, str):
            raise ValueError("hash_to_crack doit être une chaîne de caractères")

        hash_length = len(hash_to_crack)

        # Vérifications basées sur la longueur et les motifs
        if hash_length == 32:
            # Vérification pour MD5
            if re.fullmatch(r'[0-9a-fA-F]{32}', hash_to_crack):
                return 'md5'
        elif hash_length == 40:
            # Vérification pour SHA-1
            if re.fullmatch(r'[0-9a-fA-F]{40}', hash_to_crack):
                return 'sha1'
        elif hash_length == 64:
            # Vérification pour SHA-256
            if re.fullmatch(r'[0-9a-fA-F]{64}', hash_to_crack):
                return 'sha256'
        elif hash_length == 60:
            # Vérification pour bcrypt
            if hash_to_crack.startswith('$2b$') or hash_to_crack.startswith('$2a$'):
                return 'bcrypt'
        elif hash_length in (64, 96, 128):
            # Vérification pour scrypt (vérification de base64)
            if re.fullmatch(r'[A-Za-z0-9+/=]{44}', hash_to_crack):
                return 'scrypt'
        elif hash_length in (32, 64):
            # Vérification pour Argon2
            if hash_to_crack.startswith('$argon2'):
                return 'argon2'
        elif hash_length in (56, 64):
            # Vérification pour SHA3
            if re.fullmatch(r'[0-9a-fA-F]{56}', hash_to_crack) or re.fullmatch(r'[0-9a-fA-F]{64}', hash_to_crack):
                return 'sha3'
        else:
            return None

class HashCrackerApp(MDApp):
    config_file = 'config.txt'

    def build(self):
        self.theme_cls.primary_palette = 'Green'
        self.last_dictionary_file = self.load_last_dictionary()
        return Builder.load_string(KV)

    def save_last_dictionary(self, path):
        with open(self.config_file, 'w') as f:
            f.write(path)

    def load_last_dictionary(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return f.read().strip()
        return ''

    def select_dictionary_attack(self):
        self.attack_type = 'dictionary'
        self.show_file_chooser()

    def select_brute_force_attack(self):
        self.attack_type = 'brute_force'
        self.show_brute_force_options()

    def show_file_chooser(self):
        self.file_chooser = FileChooserListView(path='/', filters=['*.txt'], size_hint=(0.9, 0.9))
        
        if self.last_dictionary_file:
            self.file_chooser.path = os.path.dirname(self.last_dictionary_file)
            self.file_chooser.selection = [self.last_dictionary_file]

        select_button = MDRaisedButton(text="Select", size_hint_y=None, height=dp(50))
        select_button.bind(on_release=self.on_file_selected)

        file_popup_layout = MDBoxLayout(orientation='vertical')
        file_popup_layout.add_widget(self.file_chooser)
        file_popup_layout.add_widget(select_button)

        self.file_popup = Popup(title="Select Dictionary File", content=file_popup_layout, size_hint=(0.9, 0.9))
        self.file_popup.open()

    def on_file_selected(self, instance):
        if self.file_chooser.selection:
            self.dictionary_file = self.file_chooser.selection[0]
            self.save_last_dictionary(self.dictionary_file)
            self.file_popup.dismiss()
            self.root.ids.result_label.text = f"Selected file: {self.dictionary_file}"
        else:
            self.root.ids.result_label.text = "[-] No file selected."

    def show_brute_force_options(self):
        brute_force_layout = MDBoxLayout(orientation='vertical')
        self.length_input = MDTextField(hint_text="Max password length (default is 4)", multiline=False)
        brute_force_layout.add_widget(self.length_input)

        start_button = MDRaisedButton(text="Start Brute Force", size_hint_y=None, height=dp(50))
        start_button.bind(on_release=self.on_brute_force_selected)
        brute_force_layout.add_widget(start_button)

        self.brute_force_popup = Popup(title="Brute Force Options", content=brute_force_layout, size_hint=(0.8, 0.5))
        self.brute_force_popup.open()

    def on_brute_force_selected(self, instance):
        try:
            self.max_length = int(self.length_input.text) if self.length_input.text else 4
            self.brute_force_popup.dismiss()
            self.root.ids.result_label.text = f"Max length set to {self.max_length}"
        except ValueError:
            self.root.ids.result_label.text = "Invalid input for max length"

    def start_attack(self):
        hash_to_crack = self.root.ids.hash_input.text
        hash_cracker = HashCracker()  # Instancier HashCracker
        hash_type = hash_cracker.detect_hash_type(hash_to_crack)
        if not hash_type:
            self.root.ids.result_label.text = "[-] Unknown hash type."
            return

        self.root.ids.result_label.text = f"[+] Detected hash type: {hash_type}"

        if self.attack_type == 'dictionary':
            if not hasattr(self, 'dictionary_file'):
                self.root.ids.result_label.text = "[-] Please select a dictionary file."
                return
            self.dictionary_attack(hash_to_crack, hash_type, self.dictionary_file)
        elif self.attack_type == 'brute_force':
            result = brute_force_attack(hash_to_crack, hash_type, self.max_length)
            if result:
                self.root.ids.result_label.text = f"[+] Password found: {result}"
            else:
                self.root.ids.result_label.text = "[-] Password not found with brute force."

    def hash_password(self, password, hash_type='md5'):
        try:
            if hash_type == 'bcrypt':
                return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            elif hash_type == 'argon2':
                # Placeholder for Argon2 hashing
                pass
            elif hash_type == 'scrypt':
                # Placeholder for scrypt hashing
                pass
            else:
                hash_func = hashlib.new(hash_type)
                hash_func.update(password.encode('utf-8'))
                return hash_func.hexdigest()
        except ValueError:
            self.root.ids.result_label.text = f"[-] Hash type {hash_type} not supported."
            return None

    def dictionary_attack(self, hash_to_crack, hash_type, dictionary_file):
        try:
            with open(dictionary_file, 'r') as f:
                for line in f:
                    word = line.strip()
                    if self.hash_password(word, hash_type) == hash_to_crack:
                        self.root.ids.result_label.text = f"[+] Password found: {word}"
                        return word
        except FileNotFoundError:
            self.root.ids.result_label.text = f"[-] Dictionary file {dictionary_file} not found."
        self.root.ids.result_label.text = "[-] Password not found in dictionary."
        return None

if __name__ == '__main__':
    HashCrackerApp().run()
