import sqlite3
from python_files import algorithme_de_chiffrement
import os
from app import app
from flask import render_template
import hashlib

######### Database ##########

# Connexion à la base de données SQLite
def connect_db():
    return sqlite3.connect('users.db')

def create_user_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        rsa_public_key BLOB NOT NULL,
                        has_voted INTEGER DEFAULT 0,
                        is_admin INTEGER DEFAULT 0)''')  # Nouvelle colonne pour l'admin
    conn.commit()
    conn.close()

# Créer la table des votes si elle n'existe pas
def create_votes_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vote TEXT NOT NULL,
                        aes_key TEXT NOT NULL,
                        user_public_key BLOB NOT NULL,
                        hmac_digest TEXT NOT NULL,
                        hmac_key BLOB NOT NULL)''')
    conn.commit()
    conn.close()

# Créer un utilisateur admin par défaut si la base de données est vide
def create_admin_user():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0:  # Si aucun utilisateur n'existe, créer un admin par défaut
        username = "admin"
        password = "admin"  # Mot de passe pour l'admin
        password_usename = username + password
        
        hashed_password = hashlib.sha1(password_usename.encode()).hexdigest()
        public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()
        cursor.execute("INSERT INTO users (username, password, rsa_public_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?)", 
                       (username, hashed_password, public_key, 0, 1))  # is_admin = 1 pour admin
        conn.commit()
        conn.close()

        private_key_path = f"private_keys/{username}_private_key.pem"
        os.makedirs("private_keys", exist_ok=True)
        with open(private_key_path, "wb") as f:
            f.write(private_key)

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403