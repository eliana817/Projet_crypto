import sqlite3
from werkzeug.security import generate_password_hash
from python_files import algorithme_de_chiffrement
from hashlib import sha256
import os
import hashlib

# Function to connect to the SQLite database
def connect_db():
    return sqlite3.connect('users.db')

# Create users table
def create_user_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        rsa_public_key BLOB NOT NULL,
                        has_voted INTEGER DEFAULT 0,
                        is_admin INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

# Create votes table
def create_votes_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vote TEXT NOT NULL,
                        aes_key TEXT NOT NULL,
                        user_public_key BLOB NOT NULL)''')
    conn.commit()
    conn.close()

# Create the admin user if no users exist
def create_admin_user():
    """Creates the admin user if no user exists in the database."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0: 
        username = "admin"
        password = "admin" 
        hashed_password = hashlib.sha1(password.encode()).hexdigest()

        public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()

        cursor.execute("INSERT INTO users (username, password, rsa_public_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?)", 
                       (username, hashed_password, public_key, 0, 1))
        conn.commit()
        conn.close()

        private_key_path = f"private_keys/{username}_private_key.pem"
        os.makedirs("private_keys", exist_ok=True)
        with open(private_key_path, "wb") as f:
            f.write(private_key)

# Helper function to hash the username
def hash_username(username):
    return sha256(username.encode('utf-8')).hexdigest()

def hash_password(password):
    """Hashes a password using SHA256."""
    return sha256(password.encode('utf-8')).hexdigest()

def check_password(hashed_password, input_password):
    """Checks if a password matches a hashed password."""
    return hashed_password == sha256(input_password.encode('utf-8')).hexdigest()