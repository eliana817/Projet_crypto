# XOR cipher
def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts the plaintext with the given key using XOR."""
    return bytes([p ^ key[i % len(key)] for i, p in enumerate(plaintext)])


# Implementing CBC mode encryption
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt the plaintext using CBC mode with the given key and IV."""
    # Ensure that the plaintext is a multiple of the block size (16 bytes)
    block_size = 16
    padding_length = block_size - (len(plaintext) % block_size)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)

    ciphertext = b""
    previous_block = iv

    # Encrypt each block
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i:i + block_size]

        # XOR with the previous ciphertext block (or IV for the first block)
        block_to_encrypt = bytes([b ^ p for b, p in zip(block, previous_block)])

        # Encrypt the block using XOR (in place of AES encryption)
        encrypted_block = xor_encrypt(block_to_encrypt, key)

        ciphertext += encrypted_block
        previous_block = encrypted_block  # For next block XOR

    return ciphertext


# Decryption using CBC mode
def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt the ciphertext using CBC mode with the given key and IV."""
    block_size = 16
    plaintext = b""
    previous_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]

        # Decrypt the block using XOR (in place of AES decryption)
        decrypted_block = xor_encrypt(block, key)

        # XOR with the previous ciphertext block to retrieve the plaintext
        original_block = bytes([d ^ p for d, p in zip(decrypted_block, previous_block)])
        plaintext += original_block

        previous_block = block  # For next block decryption

    # Remove padding
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]



if __name__ == "__main__":
    # Key and IV
    key = b"YELLOW SUBMARINE"  # The key (16 bytes)
    iv = b"\x00" * 16  # The initialization vector (16 zero bytes)

    # The plaintext message
    plaintext = b"Encrypt the plaintext using CBC mode with the given key and IV"

    # Encrypt the plaintext using CBC mode
    ciphertext = cbc_encrypt(plaintext, key, iv)
    print("Ciphertext:", ciphertext.hex())

    # Decrypt the ciphertext using CBC mode
    decrypted_text = cbc_decrypt(ciphertext, key, iv)
    print("Decrypted plaintext:", decrypted_text.decode())
