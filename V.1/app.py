from flask import Flask, render_template, request, redirect, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
from Crypto.Cipher import PKCS1_OAEP
import os


app = Flask(__name__)
app.secret_key = 'secretkey'  # Nécessaire pour utiliser flash et gérer les sessions

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
                        has_voted INTEGER DEFAULT 0)''')  # Ajout de has_voted pour savoir si l'utilisateur a voté
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
                        user_public_key BLOB NOT NULL)''')
    conn.commit()
    conn.close()

# Générer une paire de clés RSA (publique et privée)
def generate_rsa_keys():
    key = RSA.generate(2048)  # Génère une clé RSA de 2048 bits
    private_key = key.export_key()  # Clé privée
    public_key = key.publickey().export_key()  # Clé publique
    return public_key, private_key

#------------------------------------------------------------------------------------------------------------------------


# Page d'accueil
@app.route('/')
def accueil():
    return render_template('accueil.html')

# Page de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  # Vérifie le mot de passe
            session['user_id'] = user[0]
            flash('Connexion réussie!', 'success')
            return redirect('/vote')  # Redirection vers la page de vote
        else:
            flash('Pseudo ou mot de passe incorrect.', 'error')
    
    return render_template('login.html')

# Page d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vérification si l'utilisateur existe déjà
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Ce pseudo est déjà pris.', 'error')
            return redirect('/register')  # Redirige vers la page d'inscription si l'utilisateur existe déjà
        
        hashed_password = generate_password_hash(password)

        # Génération de la paire de clés RSA pour cet utilisateur
        public_key, private_key = generate_rsa_keys()

        # Enregistrer le nouvel utilisateur avec la clé publique RSA et has_voted = 0
        cursor.execute("INSERT INTO users (username, password, rsa_public_key, has_voted) VALUES (?, ?, ?, ?)", 
                       (username, hashed_password, public_key, 0))
        conn.commit()
        conn.close()

        # Enregistrer la clé privée dans un fichier sécurisé (localement)
        private_key_path = f"private_keys/{username}_private_key.pem"
        os.makedirs("private_keys", exist_ok=True)
        with open(private_key_path, "wb") as f:
            f.write(private_key)

        flash('Utilisateur inscrit avec succès. Vous pouvez maintenant vous connecter.', 'success')
        return redirect('/login')  # Redirection vers la page de connexion

    return render_template('register.html')


# Page de vote (uniquement accessible si connecté)
@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user_id' not in session:
        flash('Vous devez être connecté pour voter!', 'error')
        return redirect('/login')  # Redirige vers la page de login si l'utilisateur n'est pas connecté
    
    user_id = session['user_id']

    # Vérifier si l'utilisateur a déjà voté
    if has_user_voted(user_id):
        # Afficher un message flash et empêcher de voter
        flash('Vous avez déjà voté !', 'info')
        return render_template('vote.html', has_voted=True)  # Affiche le bouton des résultats si déjà voté

    if request.method == 'POST':
        vote = request.form['vote']

        # Récupérer la clé publique RSA de l'utilisateur
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT rsa_public_key FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()

        public_key = user[0]

        # Chiffrer le vote avec AES et la clé publique RSA
        encrypted_vote, encrypted_aes_key = encrypt_vote(vote, public_key)

        # Stocker le vote chiffré et la clé publique dans la base de données
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO votes (vote, aes_key, user_public_key) VALUES (?, ?, ?)", 
                       (encrypted_vote, encrypted_aes_key, public_key))
        conn.commit()
        conn.close()

        # Marquer l'utilisateur comme ayant voté (mettre has_voted à 1)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET has_voted = 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        flash(f'Vous avez voté pour: {vote}', 'success')
        return redirect('/vote')  # Retour à la page de vote après avoir soumis le vote

    return render_template('vote.html', has_voted=False)  # Si l'utilisateur n'a pas voté, il peut encore voter

#------------------------------------------------------------------------------------------------------------------------

# Fonction de chiffrement du vote avec AES et RSA
def encrypt_vote(vote, public_key):
    # Générer une clé AES unique pour chaque vote
    aes_key = get_random_bytes(32)  # 256-bit AES key
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)  # Chiffrement AES en mode CBC
    
    # Générer un IV (vecteur d'initialisation) aléatoire pour chaque chiffrement
    iv = get_random_bytes(AES.block_size)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    # Chiffrer le vote avec l'AES
    ciphertext = cipher_aes.encrypt(pad(vote.encode(), AES.block_size))

    # Chiffrer la clé AES avec la clé publique RSA en utilisant PKCS1_OAEP
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)  # Création du cipher RSA avec padding OAEP
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)  # Chiffrement de la clé AES

    # Encoder le tout en base64 pour le stocker facilement
    encrypted_vote = base64.b64encode(iv + ciphertext).decode('utf-8')  # Préfixe avec l'IV
    encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')
    
    return encrypted_vote, encrypted_aes_key

# Fonction pour vérifier si l'utilisateur a déjà voté
def has_user_voted(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == 1


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.clear()  # Efface toutes les données de session (déconnexion)
        flash('Déconnexion réussie', 'success')
        return redirect('/')  # Redirige l'utilisateur vers la page d'accueil après la déconnexion
    return redirect('/')


@app.route('/resultats')
def resultats():
    if 'user_id' not in session:
        flash('Vous devez être connecté pour voir les résultats!', 'error')
        return redirect('/login')  # Redirige vers la page de login si l'utilisateur n'est pas connecté

    # Récupérer tous les votes de la base de données
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT vote, aes_key, user_public_key FROM votes")
    votes = cursor.fetchall()
    conn.close()

    # Déchiffrer chaque vote
    decrypted_votes = []

    for encrypted_vote, encrypted_aes_key, user_public_key in votes:
        decrypted_vote = decrypt_vote(encrypted_vote, encrypted_aes_key, user_public_key)
        decrypted_votes.append(decrypted_vote)

    # Compter les votes pour chaque option
    vote_count = {"Brioche": 0, "Ticket à Gratter": 0}
    for vote in decrypted_votes:
        if vote == "Brioche":
            vote_count["Brioche"] += 1
        elif vote == "Ticket à Gratter":
            vote_count["Ticket à Gratter"] += 1
    
    return render_template('resultats.html', vote_count=vote_count)



# Fonction de déchiffrement du vote
def decrypt_vote(encrypted_vote, encrypted_aes_key, user_public_key):
    # Charger la clé privée à partir du fichier
    username = get_username_from_public_key(user_public_key)
    private_key_path = f"private_keys/{username}_private_key.pem"
    
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Déchiffrer la clé AES avec la clé privée RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    try:
        aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
    except ValueError:
        raise ValueError("La clé RSA privée ne correspond pas à la clé utilisée pour chiffrer le vote.")

    # Déchiffrer le vote avec la clé AES
    encrypted_vote_data = base64.b64decode(encrypted_vote)
    iv = encrypted_vote_data[:AES.block_size]
    ciphertext = encrypted_vote_data[AES.block_size:]
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_vote = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')
    
    return decrypted_vote

# Fonction pour récupérer le nom d'utilisateur à partir de la clé publique
def get_username_from_public_key(public_key):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None



if __name__ == '__main__':
    create_user_table()  # Crée la table des utilisateurs à chaque démarrage de l'application
    create_votes_table()  # Crée la table des votes si elle n'existe pas
    app.run(debug=True, port=5001)
