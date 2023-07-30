from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Anahtar üretme işlemi
private_key_path = "private_key.pem"

with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,  # anahtar şifresi yoksa None olmalıdır
    )
    
# Mesaj şifreleme işlemi
def encrypt (plain_text):
    cipher_text = public_key.encrypt(
        plain_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return cipher_text

# Şifrelenmiş mesajı çözme işlemi
def decrypt (cipher_text):
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    return plain_text


message = b'Sedat'
public_key = private_key.public_key()

encrypted = encrypt(message)
#d_str = b'\x1b\xb1+\x8e\xac,\x1d\x99[\xb3\xbec{\xab\xfd\x1e$\x1c\xa3\xa0\x8c\x88\x07\r\xbc\x12\xa6\x98os\x03\xbd\x1fk\x17\xcf\xc0<]\x89yli\x9e\xa1\xc3\x84h\x05j\x82\xa6Q\xde#y\x95!\x13\x01\n\x80{\x8a\\on\xe0qC\x1e{\xc9h\xf1j\x08\x8aatG\xb2\x83\xd5\xa2\xb3V\xb9\xe0\x1d\xe7\x82*\xdaS\xc3\xbfZ1d\xb9uO\xd8\xed\xdbh,\x1a/U\xfa\x0c<@\xce\xf0\xe1\x0c\x85W\xa9\n\x9e,\xa8v\xf2\r7dR\x01\x8b\xfb[\xb3\x92Dg\xa6\x82\xa4\xe1\x837\xfb*\xfc\x0fW\xe94\x1e\x91\xb8\xec.\xa5w\x88\xb8\xfb\xc6\x1f\xac\xeaj\x82\xf2\xe6\xe7U1\xb4\xd3\x82\xe33\xd0\xfa\xc6Mj\xc96\xeeM\x8f%\xa8\xf2\xef\xf1oJ\x1d\xe9cg7[|\x1cq\x8f-FH\xc6\xd1\xaf\xa1\x99\xfc\xc0!\xaf\xb7\x11|Ynh<\xce\xdb3\x8e;aA\x08<g*\xbb4\x81\x97Cj\x01m\xac.V\xd4m\x18\xc0\xde\x10_\xa8\xcd'
decrypted = decrypt(encrypted)

print('Şifrelenmiş veri:', encrypted)
print("")
print('Çözülmüş veri:', decrypted)
