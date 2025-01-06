file = "file8.txt"

def detect_aes(file) -> None:

    with open(file, "r") as file:
        lines = file.read().splitlines()

    candidates = []

    for line in lines:
        blocks = [line[i:i+32] for i in range(0, len(line), 32)]
        unique_blocks = len(set(blocks))
        total_blocks = len(blocks)
        repetitions = total_blocks - unique_blocks

        if repetitions > 0: #si il y a des répétions, ça pourrait etre ECB
            candidates.append((line, repetitions))

    if candidates:
        candidates.sort(key=lambda x: x[1], reverse=True)
        print(f"Encoded using ECB: {candidates[0][0]}") #chaine avec la plus grande répétition, après le tri

detect_aes(file)
