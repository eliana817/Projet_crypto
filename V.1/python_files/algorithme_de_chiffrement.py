import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from python_files import database  # For database access

############# Cryptography Class ################
class Cryptography:
    # Generate RSA key pair (public and private)
    def generate_rsa_keys():
        """Generates a RSA key pair (public and private)."""
        (public_key, private_key) = rsa.newkeys(256)  # Generate RSA keys with 64 bits
        private_key_pem = private_key.save_pkcs1()  # Save the private key in PEM format
        public_key_pem = public_key.save_pkcs1()  # Save the public key in PEM format
        return public_key_pem, private_key_pem

    # Encrypt vote with AES and RSA
    def encrypt_vote(vote, public_key):
        """Encrypts a vote using AES and RSA."""
        # Generate a random AES key
        aes_key = get_random_bytes(16)  # 128-bit AES key
        cipher_aes = AES.new(aes_key, AES.MODE_ECB)  # AES encryption in ECB mode
        ciphertext = cipher_aes.encrypt(pad(vote.encode(), AES.block_size))  # Encrypt vote with AES

        # Encrypt the AES key using the public RSA key
        public_key_rsa = rsa.PublicKey.load_pkcs1(public_key)  # Load the public key from PEM
        encrypted_aes_key = rsa.encrypt(aes_key, public_key_rsa)  # Encrypt AES key with RSA

        # Base64 encode the encrypted data for storage
        encrypted_vote = base64.b64encode(ciphertext).decode('utf-8')
        encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

        return encrypted_vote, encrypted_aes_key

    # Decrypt vote with RSA and AES
    def decrypt_vote(encrypted_vote, encrypted_aes_key, public_key):
        """Decrypts a vote using RSA and AES."""
        
        # Retrieve the username from the public key
        username = Cryptography.get_username_from_public_key(public_key)
        
        private_key_path = f"private_keys/{username}_private_key.pem"

        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()

        private_key_rsa = rsa.PrivateKey.load_pkcs1(private_key_pem)  # Load private key from PEM

        try:
            # Decrypt the AES key with the private RSA key
            aes_key = rsa.decrypt(base64.b64decode(encrypted_aes_key), private_key_rsa)  # Decrypt AES key
        except rsa.DecryptionError:
            raise ValueError("Private RSA key does not match the key used to encrypt the vote.")

        # Decrypt the vote with AES using the decrypted AES key
        encrypted_vote_data = base64.b64decode(encrypted_vote)
        cipher_aes = AES.new(aes_key, AES.MODE_ECB)
        decrypted_vote = unpad(cipher_aes.decrypt(encrypted_vote_data), AES.block_size).decode('utf-8')

        return decrypted_vote

    # Retrieve the username from the public key
    @staticmethod
    def get_username_from_public_key(public_key):
        """Returns the username associated with a public RSA key."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE rsa_public_key = ?", (public_key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    # Check if the user is an administrator
    @staticmethod
    def is_admin(user_id):
        """Checks if the user is an administrator."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == 1

    # Check if the user has already voted
    @staticmethod
    def has_user_voted(user_id):
        """Checks if the user has already voted."""
        conn = database.connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT has_voted FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()

        return result and result[0] == 1
