def pkcs7_pad(plaintext: bytes, block_size: int) -> bytes:
    """Applies PKCS#7 padding to a given plaintext to match the block size."""
    # Calculate the padding size
    padding_size = block_size - (len(plaintext) % block_size)
    # Create the padding bytes
    padding = bytes([padding_size] * padding_size)
    # Return the padded plaintext
    return plaintext + padding

# Example usage
block = b"YELLOW SUBMARINE"
block_size = 20

padded_block = pkcs7_pad(block, block_size)
print(f"Padded Block: {padded_block}")