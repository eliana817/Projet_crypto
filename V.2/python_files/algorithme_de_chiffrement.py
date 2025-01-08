from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from python_files import database
import re
from hashlib import sha256

############# Functions ################
class Cryptography:

    def hash_password(password):
        """Hashes a password using SHA256."""
        return sha256(password.encode('utf-8')).hexdigest()

    def hash_username(username):
        """Hashes a username using SHA256."""
        return sha256(username.encode('utf-8')).hexdigest()

    def check_password(hashed_password, input_password):
        """Checks if a password matches a hashed password."""
        return hashed_password == sha256(input_password.encode('utf-8')).hexdigest()

    # Générer une paire de clés RSA
    def generate_rsa_keys():
        key = RSA.generate(2048)  # Génère une clé RSA de 2048 bits
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return public_key, private_key

    # Fonction de chiffrement du vote avec AES, RSA et HMAC
    
    def encrypt_vote(vote, public_key):
        aes_key = get_random_bytes(32)  # 256-bit AES key
        iv = get_random_bytes(AES.block_size)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(vote.encode(), AES.block_size))

        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        encrypted_vote = base64.b64encode(iv + ciphertext).decode('utf-8')
        encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

        hmac_key = get_random_bytes(32)
        hmac = HMAC.new(hmac_key, encrypted_vote.encode() + base64.b64decode(encrypted_aes_key), SHA256)
        hmac_digest = hmac.hexdigest()

        return encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key


    # Vérification si l'utilisateur a déjà voté
    
    def has_user_voted(user_id):
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1

    # Fonction de déchiffrement du vote
    def decrypt_vote(encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key, public_key):
        """Decrypts a vote using RSA and AES, and verifies integrity with HMAC."""
        hmac = HMAC.new(hmac_key, encrypted_vote.encode() + base64.b64decode(encrypted_aes_key), SHA256)
        calculated_hmac = hmac.hexdigest()

        if calculated_hmac != hmac_digest:
            raise ValueError("HMAC does not match. Data has been tampered with.")

        username = Cryptography.get_username_from_public_key(public_key)
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT rsa_private_key FROM users WHERE username = ?", (username,))
        private_key = cursor.fetchone()[0]
        conn.close()

        private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
        except ValueError:
            raise ValueError("Private RSA key does not match the key used to encrypt the vote.")

        encrypted_vote_data = base64.b64decode(encrypted_vote)
        iv = encrypted_vote_data[:AES.block_size]
        ciphertext = encrypted_vote_data[AES.block_size:]

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_vote = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')

        return decrypted_vote
    
    def get_username_from_public_key(public_key):
        """Returns the username from the RSA public key."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
        
        
    # Fonction pour récupérer le nom d'utilisateur à partir de la clé publique
    
    def get_username_from_public_key(public_key):
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    
    
    def is_valid_username(username):
        """Checks if the username is valid (letters, numbers, hyphens, and underscores)."""
        return bool(re.match("^[a-zA-Z0-9_-]+$", username))

      
    # Vérification si l'utilisateur est un administrateur
    def is_admin(user_id):
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1