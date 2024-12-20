cipher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

cipher_bytes = bytes.fromhex(cipher)

for k in range(256):
    decrypted = bytes([byte ^ k for byte in cipher_bytes])
    print(f"key : {k} --> , {decrypted}")