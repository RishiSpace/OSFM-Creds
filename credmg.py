import sqlite3
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os
import hashlib
import signal
import atexit
import sys

def clear_console():
    """Clears the console."""
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_key(password):
    """Generates a key from a password using PBKDF2."""
    password = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def create_database():
    """Creates a SQLite database and a table for credentials."""
    conn = sqlite3.connect('osfm-creds.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials
        (id INTEGER PRIMARY KEY, name TEXT, credential TEXT)
    ''')
    conn.commit()
    conn.close()

def encrypt(credential, key):
    """Encrypts a credential using Fernet."""
    f = Fernet(key)
    return f.encrypt(credential.encode())

def decrypt(encrypted_credential, key):
    """Decrypts an encrypted credential using Fernet."""
    f = Fernet(key)
    return f.decrypt(encrypted_credential).decode()

def store_credential(name, credential, key):
    """Stores a credential in the database."""
    encrypted_credential = encrypt(credential, key)
    conn = sqlite3.connect('osfm-creds.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO credentials (name, credential) VALUES (?, ?)', (name, encrypted_credential))
    conn.commit()
    conn.close()

def retrieve_credential(name, key):
    """Retrieves a credential from the database."""
    conn = sqlite3.connect('osfm-creds.db')
    cursor = conn.cursor()
    cursor.execute('SELECT credential FROM credentials WHERE name = ?', (name,))
    encrypted_credential = cursor.fetchone()
    if encrypted_credential:
        return decrypt(encrypted_credential[0], key)
    else:
        return None
    conn.close()

def retrieve_all_credentials(key):
    """Retrieves all credential names from the database."""
    conn = sqlite3.connect('osfm-creds.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM credentials WHERE name != "master_password"')
    credentials = cursor.fetchall()
    conn.close()
    return [credential[0] for credential in credentials]

def signal_handler(sig, frame):
    """Handles the Ctrl+C signal."""
    clear_console()
    print("Exiting program.")
    sys.exit(0)

def exit_handler():
    """Handles the exit event."""
    clear_console()
    print("Exiting program.")

def main():
    clear_console()
    master_password = getpass.getpass("Enter master password: ")
    hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()
    
    # Check if master password exists in database
    conn = sqlite3.connect('osfm-creds.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM credentials WHERE name = "master_password"')
    master_password_hash = cursor.fetchone()
    
    if master_password_hash:
        if master_password_hash[2] == hashed_master_password:
            key = generate_key(master_password)
        else:
            print("Incorrect master password.")
            return
    else:
        cursor.execute('INSERT INTO credentials (name, credential) VALUES (?, ?)', ("master_password", hashed_master_password))
        conn.commit()
        key = generate_key(master_password)
    conn.close()

    signal.signal(signal.SIGINT, signal_handler)
    atexit.register(exit_handler)

    while True:
        clear_console()
        print("1. Store credential")
        print("2. Retrieve credential")
        print("3. Retrieve all credential names")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            clear_console()
            name = input("Enter credential name: ")
            credential = getpass.getpass("Enter credential: ")
            store_credential(name, credential, key)
            print("Credential stored successfully.")
            input("Press Enter to continue...")

        elif choice == '2':
            clear_console()
            name = input("Enter credential name: ")
            credential = retrieve_credential(name, key)
            if credential:
                print("Credential:", credential)
            else:
                print("Credential not found.")
            input("Press Enter to continue...")

        elif choice == '3':
            clear_console()
            credentials = retrieve_all_credentials(key)
            if credentials:
                print("Credential names:")
                for credential in credentials:
                    print(credential)
            else:
                print("No credentials found.")
            input("Press Enter to continue...")

        elif choice == '4':
            break

        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    create_database()
    main()