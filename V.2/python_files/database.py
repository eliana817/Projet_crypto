import sqlite3
from python_files import algorithme_de_chiffrement

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
                        rsa_private_key BLOB NOT NULL,
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
    """Creates the admin user if no user exists in the database."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0:
        username = "admin"
        password = "admin"
        hashed_password = algorithme_de_chiffrement.Cryptography.hash_password(username + password)
        public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()

        # Hash the "admin" username
        hashed_username = algorithme_de_chiffrement.Cryptography.hash_username(username)

        # Convert the private key to BLOB
        rsa_private_key = private_key

        cursor.execute("INSERT INTO users (username, password, rsa_public_key, rsa_private_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?, ?)", 
                       (hashed_username, hashed_password, public_key, rsa_private_key, 0, 1))
        conn.commit()
        conn.close()


