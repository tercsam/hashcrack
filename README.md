Hash Cracker App

Overview

Hash Cracker App is a graphical user interface (GUI) application built with Kivy, designed to crack hashed passwords using two primary methods: Dictionary Attack and Brute Force Attack. The app automatically detects the hash type (MD5, SHA1, SHA256, or SHA512) based on the length of the input hash.

Features

Hash Detection: Automatically detects the type of hash based on its length.
Dictionary Attack: Uses a predefined wordlist to match the hash against possible passwords.
Brute Force Attack: Attempts to crack the hash by trying all possible combinations of characters up to a specified length.
Multithreading: The brute force attack is optimized using multithreading to speed up the cracking process.
Cross-Platform: Built with Kivy, making it compatible with Windows, macOS, Linux, and Android.

Screenshots
(I will dd screenshots of the application in action here)

Installation

a APK, APP and EXE extension will be available soon


Prerequisites
Python 3.x
pip (Python package installer)
Kivy library
Install Dependencies
Clone the Repository
bash
Copier le code
git clone https://github.com/yourusername/hash-cracker-app.git
cd hash-cracker-app
Install Kivy and Other Dependencies
bash
Copier le code
pip3 install kivy
Running the Application
To run the application locally:

bash
Copier le code
python3 hash_cracker.py
Usage

Enter the Hash: Input the hash you want to crack in the provided text field.
Select Attack Type:
Dictionary Attack: Choose this option to crack the hash using a wordlist.
Brute Force Attack: Choose this option to try all possible character combinations up to a specified length.
Start the Attack: Click the "Start Attack" button and view the results in the output section.
Dictionary Attack
Select the dictionary attack option.
Choose a dictionary file (wordlist) using the file chooser.
The app will attempt to find the password matching the given hash from the wordlist.
Brute Force Attack
Select the brute force attack option.
Specify the maximum length of the password.
The app will try all possible combinations of characters up to the specified length.
Building for Android


Contributing

Contributions are welcome! Feel free to fork the repository, make changes, and submit a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for more details.

Acknowledgements

Kivy: For providing the framework to build cross-platform applications.
Python: For its simplicity and power in building such applications.
Community: For providing numerous resources and support.
Contact

For any inquiries, please reach out to mascret.clement@gmail.com.
