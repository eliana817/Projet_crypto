from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def decrypt_aes_ecb(file_path, key):
    """Decrypt AES-128 ECB encoded file with a given key."""
    # Read and decode Base64
    with open(file_path, 'r') as file:
        encrypted_base64 = file.read().replace('\n', '')  # Remove newlines
    encrypted_bytes = base64.b64decode(encrypted_base64)  # Decode Base64

    # AES Decryption in ECB mode
    cipher = Cipher(algorithms.AES(key.encode('ascii')), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # Convert decrypted bytes to a readable string
    try:
        plaintext = decrypted_bytes.decode('ascii')
    except UnicodeDecodeError:
        plaintext = decrypted_bytes  # Return raw bytes
    return plaintext


key = "YELLOW SUBMARINE"  # Key must be exactly 16 characters (128 bits)
file_path = r'E:\Cryptographie\challenge_7.txt'

print("Decrypted Plaintext:")
print(decrypt_aes_ecb(file_path, key))
