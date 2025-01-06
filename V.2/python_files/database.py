import sqlite3

######### Database ##########

# Connexion à la base de données SQLite
def connect_db():
    return sqlite3.connect('users.db')

# Créer la table des utilisateurs si elle n'existe pas
def create_user_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        rsa_public_key BLOB NOT NULL,
                        has_voted INTEGER DEFAULT 0)''')  
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