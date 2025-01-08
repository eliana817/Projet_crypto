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
        public_key, private_key = rsa.newkeys(512)  # Génère une clé RSA de 512 bits
        return public_key.save_pkcs1(format='PEM'), private_key.save_pkcs1(format='PEM')

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