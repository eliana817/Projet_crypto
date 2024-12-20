text = "YELLOW SUBMARINE"

def pad(text, length):
    """
    Takes in text to pad and will add necessary bytes based on the length provided.

    - text: the text to pad
    - length: the length you want the text to be

    Return: Padded text
    """
    current_len = len(text)
    padding = length - (current_len % length)
    text += str(hex(padding))*padding

    return text

print(pad(text, 20))