def detect_ecb(file_path):
    """Detect ECB-encrypted ciphertext from a file."""
    with open(file_path, 'r') as file:
        lines = file.readlines()

    ecb_candidate = None
    max_repeats = 0

    for line_number, hex_ciphertext in enumerate(lines):
        hex_ciphertext = hex_ciphertext.strip()
        ciphertext_bytes = bytes.fromhex(hex_ciphertext)

        # Break into 16-byte blocks
        block_size = 16
        blocks = [ciphertext_bytes[i:i + block_size] for i in range(0, len(ciphertext_bytes), block_size)]

        # Count duplicate blocks
        repeats = len(blocks) - len(set(blocks))
        if repeats > max_repeats:
            max_repeats = repeats
            ecb_candidate = (line_number + 1, hex_ciphertext)  # Save line number and ciphertext

    if ecb_candidate:
        print(f"Detected ECB encrypted ciphertext on line {ecb_candidate[0]}:")
        print(ecb_candidate[1])
    else:
        print("No ECB-encrypted ciphertext detected.")


file_path = r'E:\Cryptographie\challenge_8.txt'
detect_ecb(file_path)
