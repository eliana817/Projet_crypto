#cipher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

#cipher_bytes = bytes.fromhex(cipher)

#for k in range(256):
#    decrypted = bytes([byte ^ k for byte in cipher_bytes])
#    print(f"key : {k} --> , {decrypted}")


# je n'ai pas encore fait le code pour les stats donc je cherche avec le mot "party" c'est de la triche

with open("exo4.txt", 'r') as file:
    for line in file:
        cipher_bytes = bytes.fromhex(line.strip())
        for k in range(256):
            decrypted = bytes([byte ^ k for byte in cipher_bytes])
            decrypted_text = decrypted.decode(errors='ignore')
            #print(decrypted_text)
            if "party" in decrypted_text.lower() :
                print(decrypted_text)