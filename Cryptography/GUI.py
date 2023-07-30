# Asimetrik şifrelemenin çözümünde hata var 

import customtkinter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")
root = customtkinter.CTk()
root.geometry("800x500")
root.title("Şifreleme")

def caesar_encrypt(text, key): 
    result = "" 
    for i in range(len(text)): 
        char = text[i]
        if char.isupper(): 
            result += chr((ord(char) + key - 65) % 26 + 65) 
        else: 
            result += chr((ord(char) + key - 97) % 26 + 97) 
    return result

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

def electronic_encrypt():
    with open('Public_Electronic.pem', 'rb') as file:
        key_electronic = file.read()
    fernet = Fernet(key_electronic)
    e_encrypted = fernet.encrypt(b'Merhaba')
    return e_encrypted

def şifre():
    string_1 = cypher_entry_1.get()
    #print(string_1)
    combo_str = combo.get()
    if combo_str == "caesar_encrypt":
        key = 3
        out_txt_1 = caesar_encrypt(string_1,key)
        #cypher_out_1.configure(require_redraw=True,text = out_txt_1)
        cypher_out_1.delete("0.0",customtkinter.END)
        cypher_out_1.insert("0.0",out_txt_1)
        #print("caesar_encrypt")
        #print("Text: ", string_1)
        #print("Encrypted Text: ", caesar_encrypt(string_1, key))    
    if combo_str == "substitution_encrypt":
        out_txt_2 = substitution_encrypt(string_1)
        #cypher_out_1.configure(text=out_txt_2)
        cypher_out_1.delete("0.0",customtkinter.END)
        cypher_out_1.insert("0.0",out_txt_2)
        #print("substitution_encrypt")
        #print("Text: ", string_1)
        #print("Encrypted Text: ", substitution_encrypt(string_1))
    if combo_str == "mono_alphabetic_encrypt":
        key_1 = "qwertyuopğüasdfghjklşizxcvbnmöç"
        c_text_1 = mono_alphabetic_encrypt(string_1,key_1)
        #cypher_out_1.configure(text=c_text_1)
        cypher_out_1.delete("0.0",customtkinter.END)
        cypher_out_1.insert("0.0",c_text_1)
        #print("mono_alphabetic_encrypt")
        #print('main text : ',string_1)
        #print('Encrypted Text: ', c_text_1)
    if combo_str == "poly_alphabetic_encrypt":
        key_2 = "Kaan Mete Malçok"
        c_text_2 = poly_alphabetic_encrypt(string_1,key_2)
        #cypher_out_1.configure(text=c_text_2)
        cypher_out_1.delete("0.0",customtkinter.END)
        cypher_out_1.insert("0.0",c_text_2)
        #print("poly_alphabetic_encrypt")
        #print("main text : ",string_1)
        #print("Encrypted Text: ", c_text_2)

def key_generator():
    combo_key_str = combo_3.get()
    if combo_key_str == "electronic_encrypt":
        global key_electronic
        key_electronic = Fernet.generate_key()
        with open('Public_Electronic.pem', 'wb') as file:
            file.write(key_electronic)
    if combo_key_str == "asymmetric_encrypt":
        global private_key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
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

def şifre_2():
    string_2 = cypher_entry_2.get()
    combo_str = combo_2.get()
    if combo_str == "electronic_encrypt":
        with open('Public_Electronic.pem', 'rb') as file:
            key = file.read()
        e_txt = string_2.encode("utf-8")
        fernet = Fernet(key)
        encrypted = fernet.encrypt(e_txt)
        #cypher_out_2.configure(text=encrypted)
        cypher_out_2.delete("0.0",customtkinter.END)
        cypher_out_2.insert("0.0",encrypted)
        #print(encrypted)
    if combo_str == "asymmetric_encrypt":
        private_key_path = "private_key.pem"
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # anahtar şifresi yoksa None olmalıdır
            )
        def a_encrypt(plain_txt):
            cipher_text = public_key.encrypt(
                plain_txt,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            return cipher_text
        a_txt = b'kaan'#string_2.encode("utf-8")
        public_key = private_key.public_key()
        a_encrypted = a_encrypt(a_txt)
        #a_encrypted_str = a_encrypted.decode("utf-8","ignore")
        #cypher_out_2.configure(text=a_encrypted)
        cypher_out_2.delete("0.0",customtkinter.END)
        cypher_out_2.insert("0.0",a_encrypted)
        print(a_encrypted)
        #print(a_encrypted)

def cozum():

    string_3 = decrypt_entry_1.get()
    combo_str = combo_4.get()
    if combo_str == "caesar_decrypt":
        key = 3
        plain_text = caesar_decrypt(string_3, key)
        #decrypt_out.configure(text=plain_text)
        decrypt_out.delete("0.0",customtkinter.END)
        decrypt_out.insert("0.0",plain_text)
    if combo_str == "electronic_decrypt":
        with open('Public_Electronic.pem', 'rb') as file:
            key = file.read()
        fernet = Fernet(key)
        decrypted = fernet.decrypt(string_3)
        #decrypt_out.configure(text=decrypted)
        decrypt_out.delete("0.0",customtkinter.END)
        decrypt_out.insert("0.0",decrypted)
    if combo_str == "asymmetric_decrypt":
        private_key_path = "private_key.pem"
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # anahtar şifresi yoksa None olmalıdır
            )
        def a_decrypt (cipher_text):
            plain_text = private_key.decrypt(
                cipher_text,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
            return plain_text
        public_key = private_key.public_key()
        string_3_byte = string_3.encode()
        a_decrypted_text = a_decrypt(string_3)
        #decrypt_out.configure(text=a_decrypted_text)
        decrypt_out.delete("0.0",customtkinter.END)
        decrypt_out.insert("0.0",a_decrypted_text)

def Exit_frame():
    root.destroy()
def Exit_OS():
    frame_2.destroy()
def Exit_NS():
    frame_3.destroy()
def Exit_CNO():
    frame_4.destroy()
def Exit_de():
    frame_5.destroy()
def OS():
    global frame_2
    frame_2 = customtkinter.CTkToplevel(root)
    frame_2.geometry("600x500")
    frame_2.title("OS")
    global cypher_entry_1
    cypher_entry_1 = customtkinter.CTkEntry(frame_2 , placeholder_text = "Cypher_1") 
    cypher_entry_1.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global combo
    combo = customtkinter.CTkComboBox(frame_2, values=["caesar_encrypt","substitution_encrypt","mono_alphabetic_encrypt","poly_alphabetic_encrypt"])
    combo.pack( padx=10  ,fill="x", expand=True)
    combo.bind(command=şifre)
    cypher_button = customtkinter.CTkButton(frame_2 , text = "şifrele" , command = şifre)
    cypher_button.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global cypher_out_1
    cypher_out_1 = customtkinter.CTkTextbox(frame_2)
    cypher_out_1.pack(pady = 12 , padx = 10 , fill = "x" , expand = True)
    #os_copy = customtkinter.CTkButton(frame_2 , text = "Copy" , command=copy_1)
    #os_copy.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    os_exit_button = customtkinter.CTkButton(frame_2 , text = "Exit" , command=Exit_OS)
    os_exit_button.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    #print("Old School")

def NS():
    global frame_3
    frame_3 = customtkinter.CTkToplevel(root)
    frame_3.geometry("600x500")
    frame_3.title("New School")
    global cypher_entry_2
    cypher_entry_2 = customtkinter.CTkEntry(frame_3 , placeholder_text = "Cypher_2")
    cypher_entry_2.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global combo_2
    combo_2 = customtkinter.CTkComboBox(frame_3, values=["electronic_encrypt","asymmetric_encrypt"])
    combo_2.pack( padx=10  ,fill="x", expand=True)
    combo_2.bind(command=şifre_2)
    cypher_button_2 = customtkinter.CTkButton(frame_3 , text = "şifrele" , command = şifre_2)
    cypher_button_2.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global cypher_out_2
    cypher_out_2 = customtkinter.CTkTextbox(frame_3)
    cypher_out_2.pack(pady = 12 , padx = 10 , fill = "x" , expand = True)
    ns_exit_button = customtkinter.CTkButton(frame_3 , text = "Exit" , command=Exit_NS)
    ns_exit_button.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    #print("New Style")

def CNO():
    global frame_4
    frame_4 = customtkinter.CTkToplevel(root)
    frame_4.geometry("600x500")
    frame_4.title("CNO")
    key_label = customtkinter.CTkLabel(frame_4,text="Choose Encryption Method",font=customtkinter.CTkFont(size=30,slant="roman"))
    key_label.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global combo_3
    combo_3 = customtkinter.CTkComboBox(frame_4, values=["electronic_encrypt","asymmetric_encrypt"])
    combo_3.pack( padx=10  ,fill="x", expand=True)
    combo_3.bind(command=key_generator)
    cypher_button_3 = customtkinter.CTkButton(frame_4 , text = "Anahtar oluştur" ,command=key_generator)
    cypher_button_3.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    cno_exit_button = customtkinter.CTkButton(frame_4, text= "Exit", command=Exit_CNO)
    cno_exit_button.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    #print("Crate New One")
    
def de():
    global frame_5
    frame_5 = customtkinter.CTkToplevel(root)
    frame_5.geometry("600x500")
    frame_5.title("Decrypt")
    global decrypt_entry_1
    decrypt_entry_1 = customtkinter.CTkEntry(frame_5 , placeholder_text = "Decrypt")
    decrypt_entry_1.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global combo_4
    combo_4 = customtkinter.CTkComboBox(frame_5, values=["caesar_decrypt","electronic_decrypt","asymmetric_decrypt"])
    combo_4.pack( padx=10  ,fill="x", expand=True)
    decrypt_button = customtkinter.CTkButton(frame_5 , text = "Çöz" , command = cozum)
    decrypt_button.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)
    global decrypt_out
    decrypt_out = customtkinter.CTkTextbox(frame_5)
    decrypt_out.pack(pady = 12 , padx = 10 , fill = "x" , expand = True)
    de_exit_button = customtkinter.CTkButton(frame_5 , text = "Exit" , command=Exit_de)
    de_exit_button.pack(pady = 12 , padx = 10 , fill = "both" , expand = True)




frame_1 = customtkinter.CTkFrame(master = root)
frame_1.pack(side= customtkinter.LEFT, fill="both", pady= 20,padx= 20 ,expand=True)
label = customtkinter.CTkLabel(master=frame_1,text="Encryption Methods",font=customtkinter.CTkFont(size=38,slant="roman"))
label.pack(pady=12 , padx=10 , fill="both" , expand=True,)
button = customtkinter.CTkButton(master=frame_1,text="Old School Encrypt" , command=OS)
button.pack(pady=12 , padx=10 , fill="both" , expand=True)
button_2 = customtkinter.CTkButton(master=frame_1,text="Crate New Key" , command=CNO)
button_2.pack(pady=12 , padx=10 , fill="both" , expand=True)
button_1 = customtkinter.CTkButton(master=frame_1,text="New School Encrypt" , command=NS)
button_1.pack(pady=12 , padx=10 , fill="both" , expand=True)
button_3 = customtkinter.CTkButton(frame_1, text="Decrypt", command=de)
button_3.pack(pady=12 , padx=10 , fill="both" , expand=True)
button_4 = customtkinter.CTkButton(frame_1, text="Exit", command=Exit_frame)
button_4.pack(pady=12 , padx=10 , fill="both" , expand=True)


root.mainloop()
