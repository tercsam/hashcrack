import hashlib
import itertools
import string

def hash_password(password, hash_type='md5'):
    hash_func = hashlib.new(hash_type)
    hash_func.update(password.encode('utf-8'))
    return hash_func.hexdigest()

def dictionary_attack(hash_to_crack, hash_type, dictionary_file):
    with open(dictionary_file, 'r') as f:
        for line in f:
            word = line.strip()
            if hash_password(word, hash_type) == hash_to_crack:
                print(f"[+] Password find : {word}")
                return word
    print("[-] password not find with dictionnaire.")
    return None

def brute_force_attack(hash_to_crack, hash_type, max_length=4):
    characters = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            guess = ''.join(guess)
            if hash_password(guess, hash_type) == hash_to_crack:
                print(f"[+] Mot de passe trouvé : {guess}")
                return guess
    print("[-] Password not find with brutforce.")
    return None

def main():
    print(r"""
     _   _           _      ____                _    
    | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | __
    | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ /
    |  _  | (_| \__ \ | | | |___| | | (_| | (__|   < 
    |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\

    """)
    
    hash_to_crack = input("Enter the Hash : ")
    hash_type = input("Enter hash type (md5, sha1, sha256, etc.) : ")
    attack_type = input("Choose attack type : 'dictionnaire' ou 'brute force' : ").strip().lower()
    
    if attack_type == 'dictionnaire':
        dictionary_file = input("Enter dictionnaire PATH : ")
        dictionary_attack(hash_to_crack, hash_type, dictionary_file)
    elif attack_type == 'brute force':
        max_length = int(input("Enter max character numb for password : "))
        brute_force_attack(hash_to_crack, hash_type, max_length)
    else:
        print("Attack type not know.")

if __name__ == "__main__":
    main()
