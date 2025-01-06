from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from python_files.database import connect_db

############# Functions ################
class Cryptography:

    # Générer une paire de clés RSA
    @staticmethod
    def generate_rsa_keys():
        key = RSA.generate(2048)  # Génère une clé RSA de 2048 bits
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return public_key, private_key

    # Fonction de chiffrement du vote avec AES, RSA et HMAC
    @staticmethod
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
    @staticmethod
    def has_user_voted(user_id):
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1

    # Fonction de déchiffrement du vote
    @staticmethod
    def decrypt_vote(encrypted_vote, encrypted_aes_key, hmac_digest, hmac_key, public_key):
        hmac = HMAC.new(hmac_key, encrypted_vote.encode() + base64.b64decode(encrypted_aes_key), SHA256)
        calculated_hmac = hmac.hexdigest()

        if calculated_hmac != hmac_digest:
            raise ValueError("L'HMAC ne correspond pas. Les données ont été modifiées.")

        username = Cryptography.get_username_from_public_key(public_key)
        private_key_path = f"private_keys/{username}_private_key.pem"
        
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
        except ValueError:
            raise ValueError("La clé RSA privée ne correspond pas à la clé utilisée pour chiffrer le vote.")

        encrypted_vote_data = base64.b64decode(encrypted_vote)
        iv = encrypted_vote_data[:AES.block_size]
        ciphertext = encrypted_vote_data[AES.block_size:]

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_vote = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')

        return decrypted_vote
    
    
    # Fonction pour récupérer le nom d'utilisateur à partir de la clé publique
    @staticmethod
    def get_username_from_public_key(public_key):
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None