def split_into_blocks(text, block_size=16):
    blocks = []
    for i in range(0, len(text), block_size):
        blocks.append(text[i:i+block_size])
    
    return len(set(blocks)) / len(blocks)

minratio = 1

with open('exo8.txt', 'r') as file:
    for line_number, line in enumerate(file, start=1):  
        text = line.strip() 
        ratio = split_into_blocks(text)  
        if ratio < minratio:
            minratio = ratio
            print(f"Ratio pour la ligne {line_number}: {minratio:.3f}") 
