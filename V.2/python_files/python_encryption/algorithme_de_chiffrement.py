from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

class Cryptography:
    @staticmethod
    def generate_aes_key():
        """Generate a random AES key."""
        return get_random_bytes(32)  # AES-256

    @staticmethod
    def encrypt_with_aes(key, plaintext):
        """Encrypt data using AES (AES-CBC mode)."""
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(Cryptography.pad(plaintext))
        return iv, ciphertext

    @staticmethod
    def decrypt_with_aes(key, iv, ciphertext):
        """Decrypt data using AES (AES-CBC mode)."""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        return Cryptography.unpad(plaintext)

    @staticmethod
    def pad(data):
        """Pad data to be a multiple of 16 bytes."""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def unpad(data):
        """Remove padding from data."""
        return data[:-data[-1]]

    @staticmethod
    def generate_rsa_keys():
        """Generate a pair of RSA keys."""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def encrypt_with_rsa(public_key, data):
        """Encrypt data using RSA."""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt_with_rsa(private_key, encrypted_data):
        """Decrypt data using RSA."""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_data)

    @staticmethod
    def generate_hmac(key, message):
        """Generate HMAC for a message using SHA-256."""
        hmac = HMAC.new(key, msg=message, digestmod=SHA256)
        return hmac.digest()

    @staticmethod
    def verify_hmac(key, message, hmac_to_verify):
        """Verify HMAC for a message."""
        hmac = HMAC.new(key, msg=message, digestmod=SHA256)
        try:
            hmac.verify(hmac_to_verify)
            return True
        except ValueError:
            return False

# Example usage (for testing purposes):
if __name__ == "__main__":
    # AES Example
    aes_key = Cryptography.generate_aes_key()
    plaintext = b"This is a message."
    iv, ciphertext = Cryptography.encrypt_with_aes(aes_key, plaintext)
    decrypted_message = Cryptography.decrypt_with_aes(aes_key, iv, ciphertext)

    print("Original:", plaintext)
    print("Decrypted:", decrypted_message)

    # RSA Example
    private_key, public_key = Cryptography.generate_rsa_keys()
    encrypted_data = Cryptography.encrypt_with_rsa(public_key, plaintext)
    decrypted_data = Cryptography.decrypt_with_rsa(private_key, encrypted_data)

    print("RSA Original:", plaintext)
    print("RSA Decrypted:", decrypted_data)

    # HMAC Example
    hmac_key = get_random_bytes(16)
    hmac_value = Cryptography.generate_hmac(hmac_key, plaintext)
    is_valid = Cryptography.verify_hmac(hmac_key, plaintext, hmac_value)

    print("HMAC Valid:", is_valid)
