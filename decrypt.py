import os
import json
import base64
import sqlite3
import shutil
import csv
import platform
from pathlib import Path
from typing import Dict, List, Optional
import argparse
from concurrent.futures import ThreadPoolExecutor
import colorama
from Cryptodome.Cipher import AES
from colorama import Fore, Style
import win32crypt

colorama.init(autoreset=True)

class BrowserPasswordDecryptor:
    def __init__(self):
        self.system = platform.system()
        
    def get_browser_path(self, browser: str, file: str) -> Optional[str]:
        paths = {
            'chrome': {
                'Windows': os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data'),
                'Darwin': '~/Library/Application Support/Google/Chrome',
                'Linux': '~/.config/google-chrome'
            },
            'edge': {
                'Windows': os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data'),
                'Darwin': '~/Library/Application Support/Microsoft Edge',
                'Linux': '~/.config/microsoft-edge'
            },
            'brave': {
                'Windows': os.path.join(os.environ['LOCALAPPDATA'], 'BraveSoftware', 'Brave-Browser', 'User Data'),
                'Darwin': '~/Library/Application Support/BraveSoftware/Brave-Browser',
                'Linux': '~/.config/BraveSoftware/Brave-Browser'
            }
        }
        
        if browser not in paths or self.system not in paths[browser]:
            return None
            
        base_path = os.path.expanduser(paths[browser][self.system])
        if file == 'Local State':
            return os.path.join(base_path, file)
        return os.path.join(base_path, 'Default', file)

    def get_profiles(self, browser: str) -> List[str]:
        base_path = self.get_browser_path(browser, '')
        if not base_path:
            return ['Default']
            
        profiles = ['Default']
        i = 1
        while os.path.exists(os.path.join(base_path, f'Profile {i}')):
            profiles.append(f'Profile {i}')
            i += 1
        return profiles

    def get_secret_key(self, browser: str) -> Optional[bytes]:
        try:
            local_state_path = self.get_browser_path(browser, 'Local State')
            if not local_state_path:
                return None

            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
                encrypted_key = local_state.get('os_crypt', {}).get('encrypted_key')
                
            if not encrypted_key:
                print(f"{Fore.RED}[ERR] {browser.title()} secret key not found{Style.RESET_ALL}")
                return None
                
            encrypted_key = base64.b64decode(encrypted_key)[5:]
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception as e:
            print(f"{Fore.RED}[ERR] {browser.title()} secret key error: {str(e)}{Style.RESET_ALL}")
            return None

    def decrypt_password(self, ciphertext: bytes, secret_key: bytes) -> str:
        try:
            iv = ciphertext[3:15]
            encrypted_pass = ciphertext[15:-16]
            cipher = AES.new(secret_key, AES.MODE_GCM, iv)
            return cipher.decrypt(encrypted_pass).decode()
        except Exception as e:
            print(f"{Fore.RED}[ERR] Password decryption failed: {str(e)}{Style.RESET_ALL}")
            return ""

    def get_firefox_passwords(self) -> List[Dict]:
        try:
            import libnss
            firefox_path = os.path.expanduser('~/.mozilla/firefox')
            profiles = [d for d in os.listdir(firefox_path) if d.endswith('.default')]
            
            if not profiles:
                print(f"{Fore.RED}[ERR] No Firefox profile found{Style.RESET_ALL}")
                return []
                
            credentials = []
            for profile in profiles:
                db_path = os.path.join(firefox_path, profile, 'logins.json')
                if not os.path.exists(db_path):
                    continue
                    
                with open(db_path, 'r') as f:
                    logins = json.load(f)
                    
                for login in logins['logins']:
                    credentials.append({
                        'url': login['hostname'],
                        'username': libnss.decrypt(login['encryptedUsername']),
                        'password': libnss.decrypt(login['encryptedPassword'])
                    })
            return credentials
        except ImportError:
            print(f"{Fore.RED}[ERR] libnss not installed. Run: pip install libnss{Style.RESET_ALL}")
            return []

    def get_chromium_passwords(self, browser: str, profile: str) -> List[Dict]:
        secret_key = self.get_secret_key(browser)
        if not secret_key:
            return []

        db_path = self.get_browser_path(browser, 'Login Data')
        if not db_path or not os.path.exists(db_path):
            print(f"{Fore.RED}[ERR] {browser.title()} database not found{Style.RESET_ALL}")
            return []

        temp_db = f"{browser}_{profile}_passwords.db"
        shutil.copy2(db_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            credentials = []
            
            for url, username, ciphertext in cursor.fetchall():
                if url and username and ciphertext:
                    password = self.decrypt_password(ciphertext, secret_key)
                    credentials.append({
                        'url': url,
                        'username': username,
                        'password': password
                    })
            
            conn.close()
            os.remove(temp_db)
            return credentials
        except Exception as e:
            print(f"{Fore.RED}[ERR] Database error: {str(e)}{Style.RESET_ALL}")
            if os.path.exists(temp_db):
                os.remove(temp_db)
            return []

    def decrypt_all(self, browsers: List[str], quiet: bool = False) -> Dict:
        results = {}
        for browser in browsers:
            if not quiet:
                print(f"Decrypting {browser.title()} passwords...")
            
            if browser == 'firefox':
                results[browser] = {'Default': self.get_firefox_passwords()}
                continue
                
            results[browser] = {}
            for profile in self.get_profiles(browser):
                if not quiet:
                    print(f"Processing profile: {profile}")
                results[browser][profile] = self.get_chromium_passwords(browser, profile)
                
        return results

def export_passwords(passwords: Dict, format: str = 'csv', output_file: str = 'passwords.csv'):
    if format == 'csv':
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['browser', 'profile', 'url', 'username', 'password'])
            writer.writeheader()
            for browser, profiles in passwords.items():
                for profile, creds in profiles.items():
                    for cred in creds:
                        writer.writerow({
                            'browser': browser,
                            'profile': profile,
                            **cred
                        })
    else:
        with open(output_file.replace('.csv', '.json'), 'w', encoding='utf-8') as f:
            json.dump(passwords, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Multi-browser password decryptor')
    parser.add_argument('-b', '--browsers', nargs='+', default=['chrome'],
                       choices=['chrome', 'edge', 'brave', 'firefox'])
    parser.add_argument('-f', '--format', choices=['csv', 'json'], default='csv')
    parser.add_argument('-o', '--output', default='passwords.csv')
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()

    decryptor = BrowserPasswordDecryptor()
    passwords = decryptor.decrypt_all(args.browsers, args.quiet)
    export_passwords(passwords, args.format, args.output)

if __name__ == '__main__':
    main()
