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
                print(f"[+] Mot de passe trouvé : {word}")
                return word
    print("[-] Mot de passe non trouvé dans le dictionnaire.")
    return None

def brute_force_attack(hash_to_crack, hash_type, max_length=4):
    characters = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            guess = ''.join(guess)
            if hash_password(guess, hash_type) == hash_to_crack:
                print(f"[+] Mot de passe trouvé : {guess}")
                return guess
    print("[-] Mot de passe non trouvé par force brute.")
    return None

def main():
    hash_to_crack = input("Entrez le hash à cracker : ")
    hash_type = input("Entrez le type de hash (md5, sha1, sha256, etc.) : ")
    attack_type = input("Choisissez l'attaque : 'dictionnaire' ou 'brute force' : ").strip().lower()
    
    if attack_type == 'dictionnaire':
        dictionary_file = input("Entrez le chemin vers le fichier dictionnaire : ")
        dictionary_attack(hash_to_crack, hash_type, dictionary_file)
    elif attack_type == 'brute force':
        max_length = int(input("Entrez la longueur maximale du mot de passe : "))
        brute_force_attack(hash_to_crack, hash_type, max_length)
    else:
        print("Type d'attaque non reconnu.")

if __name__ == "__main__":
    main()
