def mono_alphabetic_encrypt(plain_text, key):
    cipher_text = ""
    # Anahtar sözlüğü oluşturulur
    key_dict = dict(zip([chr(i) for i in range(97,123)], key))
    
    # Her harf anahtarla değiştirilir, diğer karakterler aynı kalır
    for c in plain_text:
        if c.isalpha():
            cipher_text += key_dict[c.lower()].upper() if c.isupper() else key_dict[c]
        else:
            cipher_text += c
    return cipher_text

key_1 = "qwertyuopğüasdfghjklşizxcvbnmöç"
text_1 = 'Merhaba'
c_text_1 = mono_alphabetic_encrypt(text_1,key_1)
print('main text : ',text_1)
print("key : ",key_1)
print('şifrelenmiş metin : ', c_text_1)
