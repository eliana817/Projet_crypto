from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import re
from python_files import database  # Pour l'accès à la base de données

############# Classe Cryptography ################
class Cryptography:
    # Générer une paire de clés RSA
    def generate_rsa_keys():
        """Génère une paire de clés RSA (publique et privée)."""
        key = RSA.generate(2048)  # Génère une clé RSA de 2048 bits
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return public_key, private_key

    # Fonction de chiffrement du vote avec AES, RSA et HMAC
    
    def encrypt_vote(vote, public_key):
        """Chiffre un vote avec AES et RSA, et génère un HMAC pour l'intégrité."""
        # Générer une clé AES aléatoire
        aes_key = get_random_bytes(32)  # 256-bit AES key
        iv = get_random_bytes(AES.block_size)  # Générer un vecteur d'initialisation pour AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)  # Créer un objet AES avec mode CBC
        ciphertext = cipher_aes.encrypt(pad(vote.encode(), AES.block_size))  # Chiffrement AES

        # Chiffrement de la clé AES avec la clé publique RSA
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Encodage en base64 des données chiffrées pour les stocker facilement
        encrypted_vote = base64.b64encode(iv + ciphertext).decode('utf-8')
        encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

        # Génération d'un HMAC pour l'intégrité des données
        hmac_key = get_random_bytes(32)
        hmac = HMAC.new(hmac_key, encrypted_vote.encode() + base64.b64decode(encrypted_aes_key), SHA256)
        hmac_digest = hmac.hexdigest()

        return encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key

    # Fonction de déchiffrement du vote
    def decrypt_vote(encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key, public_key):
        """Déchiffre un vote avec RSA et AES, et vérifie l'intégrité avec HMAC."""
        # Vérification de l'intégrité des données avec HMAC
        hmac = HMAC.new(hmac_key, encrypted_vote.encode() + base64.b64decode(encrypted_aes_key), SHA256)
        calculated_hmac = hmac.hexdigest()

        if calculated_hmac != hmac_digest:
            raise ValueError("HMAC does not match. Data has been tampered with.")

        # Récupérer le nom d'utilisateur en fonction de la clé publique
        username = Cryptography.get_username_from_public_key(public_key)
        
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT rsa_private_key FROM users WHERE username = ?", (username,))
        private_key = cursor.fetchone()[0]
        conn.close()

        private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            # Déchiffrer la clé AES avec la clé privée
            aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
        except ValueError:
            raise ValueError("Private RSA key does not match the key used to encrypt the vote.")

        # Déchiffrement du vote avec la clé AES
        encrypted_vote_data = base64.b64decode(encrypted_vote)
        iv = encrypted_vote_data[:AES.block_size]
        ciphertext = encrypted_vote_data[AES.block_size:]

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_vote = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')

        return decrypted_vote

    # Récupérer le nom d'utilisateur à partir de la clé publique
    @staticmethod
    def get_username_from_public_key(public_key):
        """Retourne le nom d'utilisateur associé à une clé publique RSA."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    # Vérification si le nom d'utilisateur est valide
    @staticmethod
    def is_valid_username(username):
        """Vérifie si le nom d'utilisateur est valide (lettres, chiffres, tirets et underscores seulement)."""
        return bool(re.match("^[a-zA-Z0-9_-]+$", username))

    # Vérification si l'utilisateur est un administrateur
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
        """Vérifie si l'utilisateur a déjà voté."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()

        # Si l'utilisateur existe et a voté (has_voted = 1), retourner True, sinon False
        return result and result[0] == 1

    def validate_password(password):
    # Vérifier que le mot de passe contient au moins 13 caractères
        if len(password) < 13:
            return False
        # Vérifier qu'il contient au moins une majuscule, une minuscule, un chiffre et un caractère spécial
        if not re.search(r'[A-Z]', password):  # Majuscule
            return False
        if not re.search(r'[a-z]', password):  # Minuscule
            return False
        if not re.search(r'\d', password):  # Chiffre
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Caractère spécial
            return False
        return True