README

Introduction

This Python script is designed to perform password-cracking operations using either a dictionary attack or a brute-force attack. The script supports various hashing algorithms (like md5, sha1, sha256, etc.) and can be customized according to the user's needs. It is intended for educational purposes and to demonstrate the vulnerability of weak passwords.

Prerequisites

Python 3.x
A basic understanding of hashing and password security.
A dictionary file (for dictionary attacks).
Setup

Python Installation: Ensure you have Python 3.x installed on your machine.
Dictionary File: If you plan to use the dictionary attack, prepare a dictionary file containing a list of possible passwords, one per line.
How to Use

Run the Script:
Open a terminal or command prompt.
Navigate to the directory where the script is located.
Run the script using the command: python script_name.py.
Choose Your Attack Method:
Dictionary Attack:
When prompted, enter the hash to crack.
Specify the type of hash (e.g., md5, sha1, etc.).
Select "dictionnaire" as the attack method.
Provide the path to the dictionary file.
Brute Force Attack:
When prompted, enter the hash to crack.
Specify the type of hash (e.g., md5, sha1, etc.).
Select "brute force" as the attack method.
Provide the maximum password length to try.
Interpreting the Results:
If the password is found, the script will display it.
If the password is not found, the script will inform you that the attack was unsuccessful.
Functions Overview

hash_password(password, hash_type='md5'):
Hashes the input password using the specified hashing algorithm and returns the hexadecimal digest.
dictionary_attack(hash_to_crack, hash_type, dictionary_file):
Attempts to crack the hash by comparing it against hashes of passwords in a provided dictionary file.
brute_force_attack(hash_to_crack, hash_type, max_length=4):
Attempts to crack the hash by trying all possible combinations of characters up to the specified length.
main():
Handles user input and initiates the selected attack method.
Example Usage

Dictionary Attack
bash
Copier le code
Entrez le hash à cracker : 5d41402abc4b2a76b9719d911017c592
Entrez le type de hash (md5, sha1, sha256, etc.) : md5
Choisissez l'attaque : 'dictionnaire' ou 'brute force' : dictionnaire
Entrez le chemin vers le fichier dictionnaire : /path/to/dictionary.txt
Brute Force Attack
bash
Copier le code
Entrez le hash à cracker : 5d41402abc4b2a76b9719d911017c592
Entrez le type de hash (md5, sha1, sha256, etc.) : md5
Choisissez l'attaque : 'dictionnaire' ou 'brute force' : brute force
Entrez la longueur maximale du mot de passe : 4
Notes

Performance: Brute-force attacks can be very slow, especially for longer passwords. The script is more of a proof-of-concept and not optimized for large-scale or time-sensitive operations.
Security: Use this script responsibly and only on systems or hashes that you have explicit permission to test.
Disclaimer

This script is intended for educational purposes only. The misuse of this tool is illegal and unethical. Always ensure you have permission before attempting to crack passwords. The authors are not responsible for any misuse or damage caused by this script.

AUTHOR : MASCRET Clement
