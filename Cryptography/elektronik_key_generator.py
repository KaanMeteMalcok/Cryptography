from cryptography.fernet import Fernet

# Anahtar üretme işlemi
key = Fernet.generate_key()

# Anahtarı dosyaya yazma işlemi
with open('Public_0.pem', 'wb') as file:
    file.write(key)