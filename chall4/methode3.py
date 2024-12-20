def detect_single_character_xor(file_path):
    def xor_with_key(data, key):
        """XOR a bytearray with a single-byte key."""
        return bytes([byte ^ key for byte in data])

    def score_text(text):
        """Score a piece of text based on English character frequency."""
        frequency = {
            'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
            'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
            'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
            'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
            'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
            'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
            'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
        }
        return sum([frequency.get(chr(byte).lower(), 0) for byte in text])

    # Read file
    with open(file_path, 'r') as file:
        lines = file.readlines()

    best_score = 0
    best_line = None
    best_key = None
    best_plaintext = None

    for line in lines:
        line = line.strip()  # Remove newline characters
        cipher_bytes = bytes.fromhex(line)

        for key in range(256):  # Try all possible keys
            plaintext_candidate = xor_with_key(cipher_bytes, key)
            try:
                plaintext_candidate.decode('ascii')  # Ensure valid ASCII
                score = score_text(plaintext_candidate)
                if score > best_score:
                    best_score = score
                    best_line = line
                    best_key = key
                    best_plaintext = plaintext_candidate
            except UnicodeDecodeError:
                continue

    # Print the results
    print(f"Best Line: {best_line}")
    print(f"Best Key: {best_key} ('{chr(best_key)}')")
    print(f"Decrypted Message: {best_plaintext.decode('ascii')}")


file_path = r'E:\Cryptographie\challenge_4.txt'
detect_single_character_xor(file_path)
