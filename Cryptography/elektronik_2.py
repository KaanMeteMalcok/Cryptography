from cryptography.fernet import Fernet

# Anahtarı dosyadan okuma işlemi
with open('Public_Electronic.pem', 'rb') as file:
    key = file.read()

# Şifreleme işlemi

txt = 'Merhaba'
e_txt = txt.encode("utf-8")
fernet = Fernet(key)
encrypted = fernet.encrypt(e_txt)

# Şifre çözme işlemi
decrypted = fernet.decrypt(encrypted)

print('Şifrelenmiş veri:', encrypted)
print('Çözülmüş veri:', decrypted)
