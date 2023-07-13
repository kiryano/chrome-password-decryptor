import os
import json
import base64
import sqlite3
import colorama
from Cryptodome.Cipher import AES
import shutil
import csv
import platform
from colorama import Fore, Style
import win32crypt

colorama.init(autoreset=True)

def get_chrome_local_state_path():
    system = platform.system()
    if system == 'Windows':
        return os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State')
    elif system == 'Darwin':
        return os.path.expanduser('~/Library/Application Support/Google/Chrome/Local State')
    elif system == 'Linux':
        return os.path.expanduser('~/.config/google-chrome/Local State')
    else:
        print(Fore.RED + "[ERR] Unsupported operating system." + Style.RESET_ALL)
        return None


def get_secret_key():
    try:
        chrome_local_state = get_chrome_local_state_path()
        if chrome_local_state is None:
            return None

        with open(chrome_local_state, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
            encrypted_key = local_state.get('os_crypt', {}).get('encrypted_key')
            if encrypted_key:
                encrypted_key = encrypted_key.encode('utf-8')
                encrypted_key = base64.b64decode(encrypted_key)[5:]
                secret_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                return secret_key
            else:
                print(Fore.RED + "[ERR] Chrome secret key not found in the local state file." + Style.RESET_ALL)
                return None
    except Exception as e:
        print(Fore.RED + "[ERR] Chrome secret key cannot be found:", str(e) + Style.RESET_ALL)
        return None


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = cipher.decrypt(encrypted_password).decode()
        return decrypted_pass
    except Exception as e:
        print(Fore.RED + "[ERR] Unable to decrypt password:", str(e) + Style.RESET_ALL)
        return ""


def get_db_connection(chrome_path_login_db):
    try:
        temp_login_db = "chrome_passwords.db"
        shutil.copy2(chrome_path_login_db, temp_login_db)
        return sqlite3.connect(temp_login_db)
    except Exception as e:
        print(Fore.RED + "[Error] Chrome database cannot be found:", str(e) + Style.RESET_ALL)
        return None


def get_chrome_path_login_db():
    system = platform.system()
    if system == 'Windows':
        chrome_path_login_db = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome',
                                            'User Data', 'Default', 'Login Data')
    elif system == 'Darwin':
        chrome_path_login_db = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Login Data')
    elif system == 'Linux':
        chrome_path_login_db = os.path.expanduser('~/.config/google-chrome/Default/Login Data')
    else:
        print(Fore.RED + "[Error] Unsupported operating system." + Style.RESET_ALL)
        return None

    if os.path.isfile(chrome_path_login_db):
        return chrome_path_login_db
    else:
        return None


def decrypt_chrome_passwords():
    secret_key = get_secret_key()

    chrome_path_login_db = get_chrome_path_login_db()

    if secret_key and chrome_path_login_db:
        with get_db_connection(chrome_path_login_db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()

        if rows:
            with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
                fieldnames = ["index", "url", "username", "password"]
                writer = csv.DictWriter(decrypt_password_file, fieldnames=fieldnames)
                writer.writeheader()

                for index, login in enumerate(rows):
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]

                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        print(Fore.GREEN + "Sequence:", index)
                        print(Fore.BLUE + "URL:", url)
                        print(Fore.BLUE + "Username:", username)
                        print(Fore.BLUE + "Password:", decrypted_password)
                        print("+-" * 50)

                        writer.writerow(
                            {"index": index, "url": url, "username": username, "password": decrypted_password})
        else:
            print(Fore.YELLOW + "No passwords found in the database.")
    else:
        print(Fore.RED + "Password decryption failed.")


if __name__ == '__main__':
    decrypt_chrome_passwords()
