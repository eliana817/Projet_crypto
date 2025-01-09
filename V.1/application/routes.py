from flask import Blueprint, render_template, request, redirect, flash, session, abort, make_response
from python_files import database
from python_files import algorithme_de_chiffrement
from flask import flash, redirect, render_template, request
import hashlib
import os

bp = Blueprint('routes', __name__)

####################### Paths ###################

@bp.route('/')
def homepage():
	"""Home page"""
	return render_template('homepage.html')
	

@bp.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		
		conn = database.connect_db()
		cursor = conn.cursor()
		cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.sha1(password.encode()).hexdigest()}'")
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
	"""Logout the user."""
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

		conn = database.connect_db()
		cursor = conn.cursor()
		cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
		existing_user = cursor.fetchone()

		if existing_user:
			flash('Ce pseudo est déjà pris.', 'error')
			return redirect('/register')

		# Hacher le mot de passe
		hashed_password = hashlib.sha1(password.encode()).hexdigest()

		# Générer les clés RSA
		public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()

		cursor.execute("INSERT INTO users (username, password, rsa_public_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?)", 
					   (username, hashed_password, public_key, 0, 0))  
		conn.commit()
		conn.close()

		# Enregistrer la clé privée dans un fichier sécurisé (localement)
		private_key_path = f"private_keys/{username}_private_key.pem"
		os.makedirs("private_keys", exist_ok=True)
		with open(private_key_path, "wb") as f:
			f.write(private_key)

		flash('Utilisateur inscrit avec succès. Vous pouvez maintenant vous connecter.', 'success')
		return redirect('/login')

	return render_template('register.html')


@bp.route('/results')
def results():
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
	vote_count = {"Pain au chocolat": 0, "Chocolatine": 0}
	for vote in decrypted_votes:
		if vote == "Pain au chocolat":
			vote_count["Pain au chocolat"] += 1
		elif vote == "Chocolatine":
			vote_count["Chocolatine"] += 1
	
	return render_template('results.html', vote_count=vote_count)




@bp.route('/vote', methods=['GET', 'POST'])
def vote():
	# Vérifier si l'utilisateur est connecté, sinon renvoyer une erreur 403
	if 'user_id' not in session:
		abort(403)  # Retourne une erreur 403 si l'utilisateur n'est pas connecté

	user_id = session['user_id']

	# Vérifier si l'utilisateur est un administrateur
	if algorithme_de_chiffrement.Cryptography.is_admin(user_id):
		flash('L\'administrateur ne peut pas voter.', 'info')
		return render_template('vote.html', has_voted=False, is_admin=True)  # Ne permet pas de voter à l'admin

	# Vérifier si l'utilisateur a déjà voté
	if algorithme_de_chiffrement.Cryptography.has_user_voted(user_id):
		return render_template('vote.html', has_voted=True, is_admin=False)

	if request.method == 'POST':
		vote = request.form['vote']
		conn = database.connect_db()
		cursor = conn.cursor()
		cursor.execute("SELECT rsa_public_key FROM users WHERE id = ?", (user_id,))
		user = cursor.fetchone()
		conn.close()

		public_key = user[0]

		encrypted_vote, encrypted_aes_key = algorithme_de_chiffrement.Cryptography.encrypt_vote(vote, public_key)

		# Stocker le vote chiffré et la clé publique dans la base de données
		conn = database.connect_db()
		cursor = conn.cursor()
		cursor.execute("INSERT INTO votes (vote, aes_key, user_public_key) VALUES (?, ?, ?)", 
					   (encrypted_vote, encrypted_aes_key, public_key))
		conn.commit()
		conn.close()

		# Marquer l'utilisateur comme ayant voté
		conn = database.connect_db()
		cursor = conn.cursor()
		cursor.execute("UPDATE users SET has_voted = 1 WHERE id = ?", (user_id,))
		conn.commit()
		conn.close()

		flash(f'Vous avez voté pour: {vote}', 'success')
		return redirect('/vote')

	return render_template('vote.html', has_voted=False, is_admin=False)
