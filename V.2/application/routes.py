from flask import Blueprint, render_template, request, redirect, flash, session, abort, make_response
from python_files import database
from python_files import algorithme_de_chiffrement
import logging

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

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for users."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not algorithme_de_chiffrement.Cryptography.is_valid_username(username):
            flash("Username can only contain letters, digits, hyphens, and underscores.", "error")
            return redirect('/login')

        hashed_username = algorithme_de_chiffrement.Cryptography.hash_username(username)
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (hashed_username,))
        user = cursor.fetchone()
        conn.close()

        #logging.info(f"User submitted data: {user}")

        if user and algorithme_de_chiffrement.Cryptography.check_password(user[2], username + password):
            session['user_id'] = user[0]
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect('/vote')
        else:
            flash('Incorrect username or password.', 'error')

    return render_template('login.html')



@bp.route('/logout', methods=['POST'])
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
    """User registration page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not algorithme_de_chiffrement.Cryptography.is_valid_username(username):
            flash("Username can only contain letters, digits, hyphens, and underscores.", "error")
            return redirect('/register')

        hashed_username = algorithme_de_chiffrement.Cryptography.hash_username(username)
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (hashed_username,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            flash('This username is already taken.', 'error')
            return redirect('/register')

        hashed_password = algorithme_de_chiffrement.Cryptography.hash_password(username + password)
        public_key, private_key = algorithme_de_chiffrement.Cryptography.generate_rsa_keys()

        # Save private key directly to the database
        rsa_private_key = private_key

        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, rsa_public_key, rsa_private_key, has_voted, is_admin) VALUES (?, ?, ?, ?, ?, ?)", 
                       (hashed_username, hashed_password, public_key, rsa_private_key, 0, 0))
        conn.commit()
        conn.close()

        flash('User successfully registered. You can now log in.', 'success')
        return redirect('/login')

    return render_template('register.html')

@bp.route('/results')
def results():
    """Results page for admins."""
    if 'user_id' not in session or not algorithme_de_chiffrement.Cryptography.is_admin(session['user_id']):
        abort(403)

    conn = database.connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT vote, aes_key, user_public_key, hmac_digest, hmac_key FROM votes")
    votes = cursor.fetchall()
    conn.close()

    decrypted_votes = []
    for encrypted_vote, encrypted_aes_key, user_public_key, hmac_digest, hmac_key in votes:
        decrypted_vote = algorithme_de_chiffrement.Cryptography.decrypt_vote(encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key, user_public_key)
        decrypted_votes.append(decrypted_vote)

    vote_count = {"Brioche": 0, "Ticket à Gratter": 0}
    for vote in decrypted_votes:
        if vote == "Brioche":
            vote_count["Brioche"] += 1
        elif vote == "Ticket à Gratter":
            vote_count["Ticket à Gratter"] += 1

    return render_template('resultats.html', vote_count=vote_count)



@bp.route('/vote', methods=['GET', 'POST'])
def vote():
    """Voting page for users."""
    if 'user_id' not in session:
        abort(403)

    user_id = session['user_id']

    if algorithme_de_chiffrement.Cryptography.is_admin(user_id):
        flash('Administrator cannot vote.', 'info')
        return render_template('vote.html', has_voted=False, is_admin=True)

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

        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO votes (vote, aes_key, user_public_key, hmac_digest, hmac_key) VALUES (?, ?, ?, ?, ?)", 
                       (encrypted_vote, encrypted_aes_key, public_key, hmac_digest, hmac_key))
        conn.commit()
        conn.close()

        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET has_voted = 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        flash(f'You voted for: {vote}', 'success')
        return redirect('/vote')

    return render_template('vote.html', has_voted=False, is_admin=False)


from app import app
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403