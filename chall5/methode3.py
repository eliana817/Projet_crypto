def repeating_key_xor(plaintext, key):
    """Encrypt plaintext with repeating-key XOR."""
    key_bytes = key.encode('ascii')  # Convert to bytes
    plaintext_bytes = plaintext.encode('ascii')  # Convert to bytes

    # XOR each byte of the plaintext with the repeating key
    ciphertext = bytes(
        [plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(plaintext_bytes))]
    )
    return ciphertext.hex()  # Return hex string


# Input text and key
plaintext = (
    "Burning 'em, if you ain't quick and nimble\n"
    "I go crazy when I hear a cymbal"
)
key = "ICE"
ciphertext = repeating_key_xor(plaintext, key)


print("Plaintext:")
print(plaintext)
print("\nKey:")
print(key)
print("\nCiphertext:")
print(ciphertext)
