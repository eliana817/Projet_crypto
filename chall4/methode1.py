from cryptopal.chall3.methode1 import scoring
import binascii


with open("file.txt", "r") as file:
    scores = {}
    best_score = 0
    level = 1 #get line number
    for line in file:
        line = line.strip()
        hex = binascii.unhexlify(line)
        for k in range(256):
            result = ''.join(chr(k ^ part) for part in hex)
            score = scoring(result)
            best_score = score if best_score < score else best_score
            scores[result] = [score, chr(k), level, line]
        level += 1

for key, value in scores.items():
    if value[0] == best_score:
        print("########################")
        print(f"Message: {key} \nKey: {value[1]} \nLine: {value[3]} (nbr {value[2]})")

#The message is: Now that the party is jumping
#Key: 5
#Line: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f - line 171