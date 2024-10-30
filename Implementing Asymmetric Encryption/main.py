from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Step 1: Generate Key Pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Save Keys in PEM Format
def save_key(key, filename, is_private):
    if is_private:
        pem = key.private_bytes
        (
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes
        (
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(filename, 'wb') as key_file:
        key_file.write(pem)

# Step 2: Load Keys from PEM Files
def load_private_key(filename):
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

# Step 3: Encrypt a Message with Public Key
def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Step 4: Decrypt the Message with Private Key
def decrypt_message(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Testing the Code
private_key, public_key = generate_key_pair()

# Save keys
save_key(private_key, 'private_key.pem', is_private=True)
save_key(public_key, 'public_key.pem', is_private=False)

# Load keys
loaded_private_key = load_private_key('private_key.pem')
loaded_public_key = load_public_key('public_key.pem')

# Encrypt and decrypt a message
message = "Hi Ahmed"
encrypted_message = encrypt_message(loaded_public_key, message)
print("Encrypted:", encrypted_message)

decrypted_message = decrypt_message(loaded_private_key, encrypted_message)
print("Decrypted:", decrypted_message)
