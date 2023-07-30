from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Anahtar üretme işlemi
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Anahtar dosyalarına yazma işlemi
with open('private_key.pem', 'wb') as file:
    file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open('public_key.pem', 'wb') as file:
    file.write(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
   