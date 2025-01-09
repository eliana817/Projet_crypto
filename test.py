from flask import Flask

def create_app():
    app = Flask(__name__,
            template_folder = '../templates',
            static_folder = '../static')
    
    # Set the secret key for sessions and flashes
    app.secret_key = '515bffd66952e6174d49b6440b24ccf692d4e9dd6456f3f3'
    
    # Import and register the blueprint using relative import
    from application import routes
    app.register_blueprint(routes.bp)

    return app

from Crypto.Cipher import AES
import rsa
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from python_files import database

############# Functions ################
class Cryptography:

    # Générer une paire de clés RSA
    @staticmethod
    def generate_rsa_keys():
        public_key, private_key = rsa.newkeys(256)  # Génère une clé RSA de 256 bits

        return public_key.save_pkcs1(), private_key.save_pkcs1()

    # Fonction de chiffrement du vote avec AES, RSA
    @staticmethod
    def encrypt_vote(vote, public_key):
        aes_key = get_random_bytes(16)  # 40-bit AES key
        iv = get_random_bytes(AES.block_size)
        cipher_aes = AES.new(aes_key, AES.MODE_ECB)
        ciphertext = cipher_aes.encrypt(pad(vote.encode(), AES.block_size))

        rsa_key = rsa.PublicKey.load_pkcs1(public_key)
        encrypted_aes_key = rsa.encrypt(aes_key, rsa_key)

        encrypted_vote = base64.b64encode(iv + ciphertext).decode('utf-8')
        encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

        return encrypted_vote, encrypted_aes_key

    @staticmethod
    def is_admin(user_id):
        """Vérifie si l'utilisateur est un administrateur."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1

    # Vérification si l'utilisateur a déjà voté
    @staticmethod
    def has_user_voted(user_id):
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1

    # Fonction de déchiffrement du vote
    @staticmethod
    def decrypt_vote(encrypted_vote, encrypted_aes_key, public_key):
        
        username = Cryptography.get_username_from_public_key(public_key)
        private_key_path = f"private_keys/{username}_private_key.pem"
        
        with open(private_key_path, "rb") as f:
            private_key = f.read()
        pkey = rsa.PrivateKey.load_pkcs1(private_key)

        try:
            aes_key = rsa.decrypt(base64.b64decode(encrypted_aes_key), pkey)
        except ValueError:
            raise ValueError("La clé RSA privée ne correspond pas à la clé utilisée pour chiffrer le vote.")

        encrypted_vote_data = base64.b64decode(encrypted_vote)
        iv = encrypted_vote_data[:AES.block_size]
        ciphertext = encrypted_vote_data[AES.block_size:]

        cipher_aes = AES.new(aes_key, AES.MODE_ECB)
        decrypted_vote = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')

        return decrypted_vote
    
    
    # Fonction pour récupérer le nom d'utilisateur à partir de la clé publique
    @staticmethod
    def get_username_from_public_key(public_key):
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    
import sqlite3
from python_files import algorithme_de_chiffrement
import os
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
                        user_public_key BLOB NOT NULL)''')
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
        
        hashed_password = hashlib.sha1(password.encode()).hexdigest()
        public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()
        cursor.execute("INSERT INTO users (username, password, rsa_public_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?)", 
                       (username, hashed_password, public_key, 0, 1))  # is_admin = 1 pour admin
        conn.commit()
        conn.close()

        private_key_path = f"private_keys/{username}_private_key.pem"
        os.makedirs("private_keys", exist_ok=True)
        with open(private_key_path, "wb") as f:
            f.write(private_key)


from flask import Blueprint, render_template, request, redirect, flash, session
from python_files import database
from python_files import algorithme_de_chiffrement
import os
import hashlib

bp = Blueprint('routes', __name__)

####################### Paths ###################

@bp.route('/')

def homepage():
	return render_template('homepage.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		
		conn = database.connect_db()
		cursor = conn.cursor()
		query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.sha1(password.encode()).hexdigest()}'" 
		cursor.execute(query)
		user = cursor.fetchone()
		conn.close()
		
		if user:
			session['user_id'] = user[0]  # Enregistrement de l'ID de l'utilisateur dans la session
			flash('Connexion réussie !', 'success')
			return redirect('/vote')  # Redirige vers la page de vote
		else:
			flash('Pseudo ou mot de passe incorrect.', 'error')
	
	return render_template('login.html')


@bp.route('/logout', methods=['GET', 'POST'])
def logout():
	if request.method == 'POST':
		session.clear()  # Efface toutes les données de session (déconnexion)
		flash('Déconnexion réussie', 'success')
		return redirect('/')  # Redirige l'utilisateur vers la page d'accueil après la déconnexion
	return redirect('/')

@bp.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		
		# Vérification si l'utilisateur existe déjà
		conn = database.connect_db()
		cursor = conn.cursor()
		query = f"SELECT * FROM users WHERE username = '{username}'"
		cursor.execute(query)
		existing_user = cursor.fetchone()

		if existing_user:
			flash('Ce pseudo est déjà pris.', 'error')
			return redirect('/register')  # Redirige vers la page d'inscription si l'utilisateur existe déjà
		hashed_password = hashlib.sha1(password.encode()).hexdigest()

		# Génération de la paire de clés RSA pour cet utilisateur
		public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()

		# Enregistrer le nouvel utilisateur avec la clé publique RSA et has_voted = 0
		cursor.execute("INSERT INTO users (username, password, rsa_public_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?)", (username, hashed_password, public_key, 0, 0))
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

@bp.route('/results')
def results():
	if 'user_id' not in session:
		flash('Vous devez être connecté pour voir les résultats!', 'error')
		return redirect('/login')  # Redirige vers la page de login si l'utilisateur n'est pas connecté

	# Récupérer tous les votes de la base de données
	conn = database.connect_db()
	cursor = conn.cursor()
	cursor.execute("SELECT vote, aes_key, user_public_key FROM votes")
	votes = cursor.fetchall()
	conn.close()

	# Déchiffrer chaque vote
	decrypted_votes = []

	for encrypted_vote, encrypted_aes_key, user_public_key in votes:
		decrypted_vote = algorithme_de_chiffrement.Cryptography.decrypt_vote(encrypted_vote, encrypted_aes_key, user_public_key)
		decrypted_votes.append(decrypted_vote)

	# Compter les votes pour chaque option
	vote_count = {"Pain au Chocolat": 0, "Chocolatine": 0}
	for vote in decrypted_votes:
		if vote == "Pain au Chocolat":
			vote_count["Pain au Chocolat"] += 1
		elif vote == "Chocolatine":
			vote_count["Chocolatine"] += 1
	
	return render_template('results.html', vote_count=vote_count)



@bp.route('/vote', methods=['GET', 'POST'])
def vote():
	if 'user_id' not in session:
		flash('Vous devez être connecté pour voter !', 'error')
		return redirect('/login')
	
	user_id = session['user_id']

	if algorithme_de_chiffrement.Cryptography.is_admin(user_id):
		flash('L\'administrateur ne peut pas voter.', 'info')
		return render_template('vote.html', has_voted=False, is_admin=True)  # Ne permet pas de voter à l'admin

	# Vérifier si l'utilisateur a déjà voté
	if algorithme_de_chiffrement.Cryptography.has_user_voted(user_id):
		#flash('Vous avez déjà voté !', 'info')
		return render_template('vote.html', has_voted=True, is_admin = False)

	if request.method == 'POST':
		vote = request.form['vote']
		
		conn = database.connect_db()
		cursor = conn.cursor()
		query = f"SELECT rsa_public_key FROM users WHERE id = '{user_id}'"
		cursor.execute(query)
		user = cursor.fetchone()
		conn.close()

		public_key = user[0]

		encrypted_vote, encrypted_aes_key = algorithme_de_chiffrement.Cryptography.encrypt_vote(vote, public_key)

		# Stocker le vote chiffré et la clé publique dans la base de données
		conn = database.connect_db()
		cursor = conn.cursor()
		cursor.execute("INSERT INTO votes (vote, aes_key, user_public_key) VALUES (?, ?, ?)", (encrypted_vote, encrypted_aes_key, public_key))
		conn.commit()
		conn.close()

		# Marquer l'utilisateur comme ayant voté
		conn = database.connect_db()
		cursor = conn.cursor()
		query = f"UPDATE users SET has_voted = 1 WHERE id = '{user_id}'"
		cursor.execute(query)
		conn.commit()
		conn.close()

		flash(f'Vous avez voté pour: {vote}', 'success')
		return redirect('/vote')

	return render_template('vote.html', has_voted=False, is_admin=False)


from application import create_app
from python_files import database

app = create_app()

if __name__ == '__main__':
    database.create_user_table()  # Crée la table des utilisateurs à chaque démarrage de l'application
    database.create_votes_table()  # Crée la table des votes si elle n'existe pas
    database.create_admin_user()
    app.run(debug=True, port=5001)