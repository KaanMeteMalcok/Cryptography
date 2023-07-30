def caesar_encrypt(text, key): 
    result = "" 
    for i in range(len(text)): 
        char = text[i] 
        if char.isupper(): 
            result += chr((ord(char) + key - 65) % 26 + 65) 
        else: 
            result += chr((ord(char) + key - 97) % 26 + 97) 
    return result 
  
text = "Merhaba"
key = 3

print("Text: ", text)
print("Key: ", key)
print("Encrypted Text: ", caesar_encrypt(text, key))

def caesar_decrypt(ciphertext, key):
    plaintext = ''
    for char in ciphertext:
        if char.isupper():
            plaintext += chr((ord(char) - key - 65) % 26 + 65)
        elif char.islower():
            plaintext += chr((ord(char) - key - 97) % 26 + 97)
        else:
            plaintext += char
    return plaintext


def substitution_encrypt(text):
    key = {'A': 'Q', 'B': 'Z', 'C': 'W', 'D': 'S', 'E': 'X',
           'F': 'E', 'G': 'D', 'H': 'C', 'I': 'V', 'J': 'F',
           'K': 'R', 'L': 'T', 'M': 'G', 'N': 'B', 'O': 'Y',
           'P': 'H', 'Q': 'U', 'R': 'J', 'S': 'N', 'T': 'M',
           'U': 'I', 'V': 'K', 'W': 'L', 'X': 'O', 'Y': 'P', 'Z': 'A', ' ': ' '} # Boşluk karakterinin tutulması gerekiyor.
    cipher_text = ''
    for letter in text.upper():
        cipher_text += key.get(letter, letter)
    return cipher_text.lower()


text = "Merhaba"
print("Text: ", text)
print("Encrypted Text: ", substitution_encrypt(text))
