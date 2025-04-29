import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Generate reusable DH parameters
from cryptography.hazmat.primitives import serialization
 
# Load DH parameters from file
with open("dh_params.pem", "rb") as f:
    pem_data = f.read()
    dh_parameters = serialization.load_pem_parameters(pem_data)



def generate_dh_key_pair():
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

def deserialize_public_key(peer_bytes):
    return load_pem_public_key(peer_bytes, backend=default_backend())

def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return hashlib.sha256(shared_secret).digest()

def encrypt_message(key, plaintext):
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext

def decrypt_message(key, data):
    nonce = data[:12]
    ciphertext = data[12:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None).decode()
