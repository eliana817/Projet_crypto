import codecs

var = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

b64 = codecs.encode(codecs.decode(var, 'hex'), 'base64').decode()

print(b64)

#OR
#print(f"Answer : {codecs.encode(codecs.decode(var, 'hex'), 'base64').decode()}")
