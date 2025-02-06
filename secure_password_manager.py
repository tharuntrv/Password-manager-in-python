import os
import sqlite3
import base64
import hashlib
import getpass
import secrets
import string
import time
import pyotp
import clipboard
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from zxcvbn import zxcvbn

# Constants
DB_FILE = "passwords.db"
SALT = b"random_salt_value"  # Should be securely generated
AUTO_LOGOUT_TIME = 300  # 5 minutes inactivity

def derive_key(master_password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# AES Encryption

def encrypt(data: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + (16 - len(data) % 16) * ' '
    ciphertext = encryptor.update(padded_data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def decrypt(enc_data: str, key: bytes) -> str:
    raw = base64.b64decode(enc_data)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext).decode().strip()

# Generate Secure Password
def generate_password(length=16, use_specials=True) -> str:
    characters = string.ascii_letters + string.digits
    if use_specials:
        characters += string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Password Strength Checker
def check_password_strength(password):
    result = zxcvbn(password)
    print(f"Password Strength: {result['score']} / 4")
    print("Feedback:", result['feedback']['suggestions'])

# Initialize Database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT UNIQUE,
            username TEXT,
            password TEXT,
            history TEXT
        )
    """)
    conn.commit()
    conn.close()

# Store Password
def store_password(service, username, password, key):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    enc_password = encrypt(password, key)
    cursor.execute("SELECT password FROM passwords WHERE service = ?", (service,))
    existing = cursor.fetchone()
    history = existing[0] if existing else ""
    
    cursor.execute("REPLACE INTO passwords (service, username, password, history) VALUES (?, ?, ?, ?)", 
                   (service, username, enc_password, history + "|" + enc_password if history else enc_password))
    conn.commit()
    conn.close()
    print(f"Password for {service} stored securely.")

# Retrieve Password
def retrieve_password(service, key):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM passwords WHERE service = ?", (service,))
    result = cursor.fetchone()
    conn.close()
    if result:
        username, enc_password = result
        password = decrypt(enc_password, key)
        print(f"Service: {service}\nUsername: {username}\nPassword: {password}")
        clipboard.copy(password)
        print("Password copied to clipboard (auto-clears in 10s).")
        time.sleep(10)
        clipboard.copy("")
    else:
        print("No password found for this service.")

# Auto Logout
def auto_logout():
    print("Auto-logout due to inactivity.")
    exit()

# Two-Factor Authentication (TOTP)
def setup_2fa():
    secret = pyotp.random_base32()
    print(f"Your 2FA Secret Key (save this!): {secret}")
    return secret

def verify_2fa(secret):
    totp = pyotp.TOTP(secret)
    code = input("Enter 2FA Code: ")
    return totp.verify(code)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--store", help="Store a password", nargs=3, metavar=("SERVICE", "USERNAME", "PASSWORD"))
    parser.add_argument("--retrieve", help="Retrieve a password", metavar="SERVICE")
    args = parser.parse_args()
    
    init_db()
    master_password = getpass.getpass("Enter master password: ")
    key = derive_key(master_password)
    
    if args.store:
        store_password(*args.store, key)
        return
    
    if args.retrieve:
        retrieve_password(args.retrieve, key)
        return
    
    last_activity = time.time()
    while True:
        if time.time() - last_activity > AUTO_LOGOUT_TIME:
            auto_logout()
        
        print("\n1. Generate Password\n2. Store Password\n3. Retrieve Password\n4. Setup 2FA\n5. Exit")
        choice = input("Select an option: ")
        last_activity = time.time()
        
        if choice == '1':
            length = int(input("Enter password length: "))
            use_specials = input("Include special characters? (y/n): ").lower() == 'y'
            password = generate_password(length, use_specials)
            print("Generated Password:", password)
            check_password_strength(password)
        elif choice == '2':
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password (leave blank to generate): ") or generate_password()
            store_password(service, username, password, key)
        elif choice == '3':
            service = input("Enter service name to retrieve: ")
            retrieve_password(service, key)
        elif choice == '4':
            secret = setup_2fa()
            print("2FA setup complete. Store this key securely.")
        elif choice == '5':
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()
