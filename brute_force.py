import time
import hashlib
from werkzeug.security import check_password_hash
from tqdm import tqdm  # For progress tracking
from itertools import product
import os
import requests


# Validate that the wordlist file exists
def validate_wordlist_file(filepath):
    if os.path.isfile(filepath):
        return True
    print(f"[!] Invalid file path: {filepath}. Please provide a valid local wordlist file.")
    return False


# Download wordlist from a URL
def download_wordlist(url, save_path="downloaded_wordlist.txt"):
    try:
        print(f"[+] Downloading wordlist from: {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Raise exception for HTTP errors
        with open(save_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(f"[+] Wordlist downloaded and saved as: {save_path}")
        return save_path
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to download wordlist: {e}")
        return None


# Hybrid cracking (dictionary + brute force)
def hybrid_cracking(hashed_password, password_file, hash_type, max_length=3):
    passwords_tested = 0
    start_time = time.time()

    try:
        # Dictionary attack
        print("\n[+] Starting dictionary attack...")
        with open(password_file, "r", encoding="utf-8", errors="ignore") as file:
            for line in tqdm(file, desc="Dictionary attack", leave=True):
                word = line.strip()
                passwords_tested += 1
                if verify_hash(hash_type, hashed_password, word):
                    print(f"\n[+] Password found using dictionary: {word}")
                    print(f"[+] Total passwords tested: {passwords_tested}")
                    print(f"[+] Time taken: {time.time() - start_time:.2f} seconds")
                    return True  # Exit after success

    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {password_file}")
        return False
    except OSError as e:
        print(f"[!] Error opening wordlist file: {e}")
        return False

    # Brute-force attack
    print("\n[!] Dictionary attack failed. Starting brute-force attack...")
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    for length in range(1, max_length + 1):
        for attempt in product(characters, repeat=length):
            word = ''.join(attempt)
            passwords_tested += 1
            if verify_hash(hash_type, hashed_password, word):
                print(f"\n[+] Password found using brute-force: {word}")
                print(f"[+] Total passwords tested: {passwords_tested}")
                print(f"[+] Time taken: {time.time() - start_time:.2f} seconds")
                return True  # Exit after success

    print("\n[!] Password not found.")
    print(f"[!] Total passwords tested: {passwords_tested}")
    print(f"[!] Time taken: {time.time() - start_time:.2f} seconds")
    return False  # Indicate failure


# Verify password against hash
def verify_hash(hash_type, hashed_password, password):
    if hash_type == "pbkdf2":
        return check_password_hash(hashed_password, password)
    elif hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest() == hashed_password
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest() == hashed_password
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")


# Display menu options
def menu():
    print("\n[+] Welcome to Password Cracker Tool")
    print("[1] Enter Hash")
    print("[2] Select Hashing Algorithm")
    print("[3] Select Wordlist File (Local File or URL)")
    print("[4] Set Maximum Brute-Force Length")
    print("[5] Start Cracking")
    print("[6] Exit")
    print()


if __name__ == "__main__":
    hashed_password = None
    hash_type = None
    password_file = None
    max_length = 3

    try:
        while True:
            menu()
            choice = input("[+] Enter your choice: ")

            if choice == "1":
                hashed_password = input("[+] Enter the hashed password: ").strip()
                print(f"[+] Hash set to: {hashed_password}")
            elif choice == "2":
                print("\n[+] Supported hash types: pbkdf2, md5, sha256")
                hash_type = input("[+] Enter the hash type: ").strip().lower()
                if hash_type in ["pbkdf2", "md5", "sha256"]:
                    print(f"[+] Hash type set to: {hash_type}")
                else:
                    print("[!] Unsupported hash type. Try again.")
                    hash_type = None
            elif choice == "3":
                file_or_url = input("[+] Enter the path to the wordlist file or URL: ").strip()
                if file_or_url.startswith("http://") or file_or_url.startswith("https://"):
                    downloaded_file = download_wordlist(file_or_url)
                    if downloaded_file:
                        password_file = downloaded_file
                elif validate_wordlist_file(file_or_url):
                    password_file = file_or_url
                else:
                    password_file = None
            elif choice == "4":
                try:
                    max_length = int(input("[+] Enter the maximum length for brute-force passwords: "))
                    print(f"[+] Max brute-force length set to: {max_length}")
                except ValueError:
                    print("[!] Invalid input. Please enter a number.")
            elif choice == "5":
                if not hashed_password or not hash_type or not password_file:
                    print("\n[!] Please ensure all inputs are set (hash, hash type, wordlist).")
                else:
                    print("\n[+] Starting hybrid cracking (dictionary + brute-force)...")
                    success = hybrid_cracking(hashed_password, password_file, hash_type, max_length)
                    if success:
                        print("\n[+] Cracking process completed successfully.")
                    else:
                        print("\n[!] Cracking process failed. Password not found.")
            elif choice == "6":
                print("[+] Exiting. Goodbye!")
                break
            else:
                print("[!] Invalid choice. Please select from the menu.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
