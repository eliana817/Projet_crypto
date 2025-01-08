from flask import Blueprint, render_template, request, redirect, flash, session, abort, make_response
from python_files import database
from python_files import algorithme_de_chiffrement
from flask import flash, redirect, render_template, request
import logging
import html

bp = Blueprint('routes', __name__)

####################### Paths ###################

@bp.before_request
def log_user_activity():
    user_ip = request.remote_addr
    user_agent = request.user_agent.string
    logging.info(f"User accessed {request.path} from {user_ip} using {user_agent}")

@bp.route('/')
def homepage():
    """Home page with user login verification."""
    is_logged_in = 'user_id' in session
    username = session.get('username', None)
    admin_status = False

    if is_logged_in:
        user_id = session['user_id']
        admin_status = algorithme_de_chiffrement.Cryptography.is_admin(user_id)

    return render_template('homepage.html', is_logged_in=is_logged_in, username=username, is_admin=admin_status)
    
@bp.route('/set-admin-password', methods=['GET', 'POST'])
def set_admin_password():
    # Vérifier si l'utilisateur est connecté et si c'est un admin, sinon renvoyer une erreur 403
    if 'user_id' not in session or not algorithme_de_chiffrement.Cryptography.is_admin(session['user_id']):
        abort(403)  # Retourne une erreur 403 si l'utilisateur n'est pas connecté

    # Vérifier si l'admin a déjà changé son mot de passe
    if 'admin_password_reset' in session and session['admin_password_reset'] == True:
        flash('Vous avez déjà réinitialisé votre mot de passe. Vous pouvez vous connecter maintenant.', 'info')
        return redirect('/vote')  # Redirige vers la page de connexion

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Vérifier que les mots de passe correspondent
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'error')
            return redirect('/set-admin-password')

        # Vérifier la force du mot de passe (au moins 13 caractères, majuscule, minuscule, chiffres, caractères spéciaux)
        if not algorithme_de_chiffrement.Cryptography.validate_password(password):
            flash("Le mot de passe doit contenir au moins 13 caractères, incluant des majuscules, des minuscules, des chiffres et des caractères spéciaux.", "error")
            return redirect('/set-admin-password')

        username = "admin"
        # Hacher le mot de passe
        hashed_password = database.hash_password(username + password)

        # Mettre à jour le mot de passe dans la base de données pour l'admin
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ?, has_voted = 1 WHERE username = ?", (hashed_password, database.hash_username(session['username'])))
        conn.commit()
        conn.close()

        # Marquer dans la session que le mot de passe a été réinitialisé
        session['admin_password_reset'] = True

        # Informer l'utilisateur que le mot de passe a été changé
        flash('Mot de passe mis à jour avec succès !', 'success')

        return redirect('/login')  # Redirige vers la page de connexion

    return render_template('sjtrj45ku54h63az5s2h1d3/new_password_admin.html')  # Affiche la page de changement de mot de passe


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Sanitize les entrées (nom d'utilisateur et mot de passe)
        username = html.escape(username)  # Échapper les caractères spéciaux dans le pseudo
        password = html.escape(password)  # Échapper les caractères spéciaux dans le mot de passe

        # Vérifier si le nom d'utilisateur est valide
        if not algorithme_de_chiffrement.Cryptography.is_valid_username(username):
            flash("Le pseudo ne peut contenir que des lettres, des chiffres, des tirets et des underscores.", "error")
            return redirect('/login')

        hashed_username = database.hash_username(username)  # Hashage sécurisé du pseudo
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (hashed_username,))
        user = cursor.fetchone()
        conn.close()

        if user and database.check_password(user[2], username + password):  # Vérifier si les mots de passe correspondent
            session['user_id'] = user[0]  # Enregistrement de l'ID de l'utilisateur dans la session
            session['username'] = username

            # Vérification si c'est la première connexion de l'admin
            if user[6] == 1 and user[5] == 0:  # Le champ 'has_voted' ou un autre champ que vous utilisez pour identifier la première connexion
                flash('Veuillez définir un nouveau mot de passe pour l\'administrateur.', 'warning')
                return redirect('/set-admin-password')  # Redirige vers la page de définition du mot de passe

            flash('Connexion réussie !', 'success')
            return redirect('/vote')  # Redirige vers la page de vote

        else:
            flash('Pseudo ou mot de passe incorrect.', 'error')
    
    return render_template('login.html')


@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout the user."""
    session.clear()
    response = make_response(redirect('/'))
    response.set_cookie('session', '', max_age=0)
    response.delete_cookie('session')

    flash('Logout successful', 'success')
    return response

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Sanitize le mot de passe et le nom d'utilisateur pour éviter l'injection de code
        username = html.escape(username)  # Échappe les caractères spéciaux dans le pseudo
        password = html.escape(password)  # Échappe les caractères spéciaux dans le mot de passe
        
        # Vérifier si le nom d'utilisateur est valide
        if not algorithme_de_chiffrement.Cryptography.is_valid_username(username):
            flash("Le pseudo ne peut contenir que des lettres, des chiffres, des tirets et des underscores.", "error")
            return redirect('/register')

        # Validation du mot de passe
        if not algorithme_de_chiffrement.Cryptography.validate_password(password):
            flash("Le mot de passe doit contenir au moins 13 caractères, incluant des majuscules, des minuscules, des chiffres et des caractères spéciaux.", "error")
            return redirect('/register')

        hashed_username = database.hash_username(username)  # Hashage sécurisé du pseudo
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (hashed_username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Ce pseudo est déjà pris.', 'error')
            return redirect('/register')

        # Hacher le mot de passe
        hashed_password = database.hash_password(username + password)  # Hachage sécurisé du mot de passe

        # Générer les clés RSA
        public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()

        cursor.execute("INSERT INTO users (username, password, rsa_public_key, rsa_private_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?, ?)", 
                       (hashed_username, hashed_password, public_key, private_key, 0, 0))  # Ajouter rsa_private_key
        conn.commit()
        conn.close()

        flash('Utilisateur inscrit avec succès. Vous pouvez maintenant vous connecter.', 'success')
        return redirect('/login')

    return render_template('register.html')


@bp.route('/results')
def results():
    # Vérifier si l'utilisateur est connecté, sinon renvoyer une erreur 403
    if 'user_id' not in session or not algorithme_de_chiffrement.Cryptography.is_admin(session['user_id']):
        abort(403)  # Retourne une erreur 403 si l'utilisateur n'est pas connecté

    # Récupérer tous les votes de la base de données
    conn = database.connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT vote, aes_key, user_public_key, hmac_digest, hmac_key FROM votes")
    votes = cursor.fetchall()
    conn.close()

    # Déchiffrer chaque vote
    decrypted_votes = []

    for encrypted_vote, encrypted_aes_key, user_public_key, hmac_digest, hmac_key in votes:
        decrypted_vote = algorithme_de_chiffrement.Cryptography.decrypt_vote(encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key, user_public_key)
        decrypted_votes.append(decrypted_vote)

    # Compter les votes pour chaque option
    vote_count = {"Brioche": 0, "Ticket à Gratter": 0}
    for vote in decrypted_votes:
        if vote == "Brioche":
            vote_count["Brioche"] += 1
        elif vote == "Ticket à Gratter":
            vote_count["Ticket à Gratter"] += 1
    
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

        encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key = algorithme_de_chiffrement.Cryptography.encrypt_vote(vote, public_key)

        # Stocker le vote chiffré et la clé publique dans la base de données
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO votes (vote, aes_key, user_public_key, hmac_digest, hmac_key) VALUES (?, ?, ?, ?, ?)", 
                       (encrypted_vote, encrypted_aes_key, public_key, hmac_digest, hmac_key))
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
