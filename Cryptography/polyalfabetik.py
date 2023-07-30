def poly_alphabetic_encrypt(plain_text, key):
    cipher_text = ""
    key_len = len(key)
    # Her karakter anahtarın ilgili karakteriyle değiştirilir
    for i, c in enumerate(plain_text):
        if c.isalpha():
            shift = ord(key[i%key_len]) - 97
            cipher_text += chr((ord(c.lower()) + shift - 97) % 26 + 97).upper() if c.isupper() else chr((ord(c.lower()) + shift - 97) % 26 + 97)
        else:
            cipher_text += c
    return cipher_text

key_1 = "Kaan Mete Malçok"
text_1 = "Merhaba"
c_text_1 = poly_alphabetic_encrypt(text_1,key_1)
print("main text : ",text_1)
print("key : ",key_1)
print("şifrelenmiş metin : ",c_text_1)