
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
import sqlite3
import hashlib
import time



class Database:
    # Database initialization and schema setup
    def initialize_database(self):
        connection = sqlite3.connect('storage.db')
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('regular', 'admin'))
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                user_id TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                file_data BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        connection.commit()
        print("[+] Success! Database Initialized")
        return connection

    def register_user(self, username, password, role):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        # Check if the username already exists
        cursor.execute('SELECT * FROM Users WHERE username=?', (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            print("[-] Error: Username already exists.")
            return False
        else:
            # Hash the password before storing it
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            # Insert the new user into the database
            cursor.execute('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
            conn.commit()
            print("[+] User registered successfully")
            return True
        conn.close()

    def authenticate_user(self, username, password, role):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        # Retrieve the user's hashed password from the database
        cursor.execute('SELECT password FROM Users WHERE username=?', (username,))
        user_data = cursor.fetchone()
        if user_data:
            hashed_password = user_data[0]
            # Hash the provided password and compare it with the stored hash
            if hashlib.sha256(password.encode()).hexdigest() == hashed_password:
                print("[+] User authenticated successfully")
                return True
            else:
                print("[-] Error: Incorrect password")
                return False
        else:
            print("[-] Error: User not found")
            return False
            conn.rollback()
        conn.close()

    def store_file(self, case_id, user_id, file_name, file_data):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Insert the file data into the Files table
            cursor.execute('INSERT INTO cases (case_id, user_id, file_name, file_data) VALUES (?, ?, ?, ?)',
                           (case_id, user_id, file_name, file_data))
            conn.commit()
            print("[+] File stored successfully")
        except sqlite3.Error as e:
            print("[-] Error storing file:", e)
            conn.rollback()
        conn.close()

    def retrieve_file(self, file_id):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Retrieve file data from the Files table
            cursor.execute('SELECT file_name, file_data FROM cases WHERE case_id = ?', (file_id,))
            # encrypted_data = cursor.fetchone()[0]
            file_row = cursor.fetchone()
            if file_row:
                file_name, file_data = file_row
                # Write file data to disk
                data = open(file_name, 'wb').write(file_data)
                print(f"[+] File '{file_name}' retrieved successfully")
            else:
                print("[-] File not found.")
        except sqlite3.Error as e:
            print("[-] Error retrieving file:", e)
            conn.rollback()
        conn.close()
        return file_name, file_data

    def list_files(self):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Retrieve all file names from the Files table
            cursor.execute('SELECT case_id, file_name FROM cases')
            files = cursor.fetchall()
            if files:
                print("List of files:")
                for file_id, file_name in files:
                    print(f"[+] File ID: {file_id}, File Name: {file_name}")
            else:
                print("[-] No files found in the database")
        except sqlite3.Error as e:
            print("[-] Error listing files:", e)
            conn.rollback()
        conn.close()

    def store_keys(self, private_key, public_key, user_id):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Insert the file data into the Files table
            cursor.execute('INSERT INTO keys (private_key, public_key, user_id) VALUES (?, ?, ?)',
                           (private_key, public_key, user_id))
            conn.commit()
            print("[+] Keys stored successfully in database")
        except sqlite3.Error as e:
            print("[-] Error storing keys:", e)
            conn.rollback()
        conn.close()

    def retrieve_private_key(self, user_id):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Retrieve file data from the Files table
            cursor.execute('SELECT private_key FROM keys WHERE user_id=?',(user_id,))
            private_key = cursor.fetchone()[0]
            if private_key:
                print("[+] Private key retrieved successfully")
                return private_key
            else:
                print("[-] File not found")
        except sqlite3.Error as e:
            print("[-] Error retrieving file:", e)
            conn.rollback()
            return None
        conn.close()

    def retrieve_public_key(self, user_id):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Retrieve file data from the Files table
            cursor.execute('SELECT public_key FROM keys WHERE user_id=?',(user_id,))
            public_key = cursor.fetchone()[0]
            if public_key:
                print("[+] Public_key key retrieved successfully")
                return public_key
            else:
                print("[-] File not found")
        except sqlite3.Error as e:
            print("[-] Error retrieving file:", e)
            conn.rollback()
            return None
        conn.close()

    def get_user_id(self, username):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            # Retrieve the user's id
            cursor.execute('SELECT id FROM users WHERE username=?', (username,))
            user_id = cursor.fetchone()
            if user_id:
                return user_id[0]
            else:
                print("[-] User ID not found")
        except sqlite3.Error as e:
            print("[-] Error retrieving file:", e)
            conn.rollback()
            return None
        conn.close()

    def get_case_userId(self, case_id):
        conn = sqlite3.connect('storage.db')
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT user_id FROM cases WHERE case_id=?', (case_id,))
            user_id = cursor.fetchone()
            if user_id:
                return user_id[0]
            else:
                print("[-] User ID not found.")
        except sqlite3.Error as e:
            print("[-] Error retrieving file:", e)
            conn.rollback()
            return None
        conn.close()


class FileManager:
    def read_file(self, filename):
        try:
            with open(filename, 'rb') as file:
                return file.read()
        except FileNotFoundError:
            print(f"[-] Error: File '{filename}' not found.")
            return None

    def write_file(self, filename, data):
        try:
            with open(filename, 'wb') as file:
                file.write(data)
        except Exception as e:
            print(f"[-] Error: Failed to write data to file '{filename}'.")
            print(e)

class KeyManager:
    def generate_key_pair(self, key_size=2048):
        key = RSA.generate(key_size)
        return key

    def serialize_key(self, key):
        return key.export_key()

    def deserialize_key(self, serialized_key):
        return RSA.import_key(serialized_key)



class EncryptionManager:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def generate_hash(self, data):
        hash_object = SHA256.new()
        hash_object.update(data)
        return hash_object.digest()

    def verify_integrity(self, data, original_hash):
        current_hash = self.generate_hash(data)
        return current_hash == original_hash

    def encrypt_file(self, filename, output_filename, case_id, user_id, public_key):
        if public_key:
            try:
                data = FileManager().read_file(filename)
                original_hash = self.generate_hash(data)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                session_key = get_random_bytes(16)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                enc_session_key = cipher_rsa.encrypt(session_key)
                encrypted_data = enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash
                print(f"[+] Encryption successful. Encrypted file saved as '{output_filename}'")
                Database().store_file(case_id, user_id, output_filename, encrypted_data)
            except Exception as e:
                print("[-] Error: Encryption failed.")
                print(e)

    def decrypt_file(self, private_key, output_filename, encrypted_data):
        if private_key:
            try:
                enc_session_key, nonce, tag, ciphertext, original_hash = (
                    encrypted_data[:private_key.size_in_bytes()],
                    encrypted_data[private_key.size_in_bytes():private_key.size_in_bytes()+16],
                    encrypted_data[private_key.size_in_bytes()+16:private_key.size_in_bytes()+32],
                    encrypted_data[private_key.size_in_bytes()+32:-32],
                    encrypted_data[-32:]
                )
                cipher_rsa = PKCS1_OAEP.new(private_key)
                session_key = cipher_rsa.decrypt(enc_session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                if self.verify_integrity(decrypted_data, original_hash):
                    FileManager().write_file(output_filename, decrypted_data)
                    print(f"[+] Integrity Check...")
                    time.sleep(1)
                    print("[+] Passed!")
                    print(f"[+] Decryption successful. Decrypted file saved as '{output_filename}'.")
                else:
                    print("[-] Error: Decryption failed due to file integrity check. The file may have been tampered with.")
            except Exception as e:
                print("[-] Error: Decryption failed.")
                print(e)

# Instantiate FileManager, KeyManager, and EncryptionManager
def main():
    print("\n<<< HYBRID ENCRYPTION DATA FORENSIC TOOL >>>\n")
    database = Database()
    database.initialize_database()
    file_manager = FileManager()
    key_manager = KeyManager()
    encryption_manager = EncryptionManager(key_manager)

    while True:
        print("---" * 15)
        print("[+] ...Program Running...")
        print("---" * 15)
        print("\n[-] Menu:\n")
        print("[+] 1. Register")
        print("[+] 2. Login")
        print("[+] 3. Exit")

        user_input = input("[-] Select Option: ")

        if user_input == "1":
            # Register New User
            print("[+] Registering New User\n")
            username = input('[-] Username: ')
            passowrd = input('[-] Password: ')
            role = input('[-] Role: ')
            database.register_user(username, passowrd, role)

            # Generate User's Private & Public Key
            private_key = key_manager.generate_key_pair(2048)
            public_key = private_key.publickey()
            serialized_pv_key = key_manager.serialize_key(private_key)
            serialized_pb_key = key_manager.serialize_key(public_key)

            # Store Keys to the database
            user_id = database.get_user_id(username)
            database.store_keys(serialized_pv_key, serialized_pb_key, user_id)

        elif user_input == "2":
            # Authenticate Existing User
            print("\n[+] Authenticating User\n")
            username = input('[-] Username: ')
            password = input('[-] Password: ')
            role = input('[-] Role: ')
            database.authenticate_user(username, password, role)

            while True:
                try:
                    if role == "regular":
                        print("\n[+] Follow prompts to encrypt file\n")
                        filename = input("[-] Enter the filename to encrypt: ")
                        output_filename = input("[-] Enter the output filename for the encrypted file: ")
                        case_id = input("[-] Enter case ID: ")
                        user_id = database.get_user_id(username)
                        public_key = database.retrieve_public_key(user_id)
                        retrieved_pb_key = key_manager.deserialize_key(public_key)
                        print(f"[+] {retrieved_pb_key}")
                        encryption_manager.encrypt_file(filename, output_filename, case_id, user_id, retrieved_pb_key)
                        print("\n[-] Press CTRL + C to logout")
                        time.sleep(1)

                    if role == "admin":
                        print("\n[+] Follow prompts to decrypt file\n")
                        case_id = input("[-] Enter case ID: ")
                        user_id = database.get_case_userId(case_id)
                        private_key = database.retrieve_private_key(user_id)
                        retrieved_pv_key = key_manager.deserialize_key(private_key)
                        print(f"[+] {retrieved_pv_key}")
                        output_filename, encrypted_data = database.retrieve_file(case_id)
                        encryption_manager.decrypt_file(retrieved_pv_key, output_filename, encrypted_data)
                        print("\n[-] Press CTRL + C to logout")
                        time.sleep(1)

                except KeyboardInterrupt:
                    print("\n[+] CTRL + C detected \n\tLogging out...")
                    break

        elif user_input == '3':
            print("\n[+] Exiting the program. \n\t ...")
            return

        else:
            print("[-] Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
