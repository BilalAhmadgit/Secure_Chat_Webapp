from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

app = Flask(__name__)

# Load secret key (32 bytes)
SECRET_KEY = os.environ.get('SECRET_KEY', '0' * 32).encode()

# In-memory list to store encrypted messages
messages = []

# Encrypt a message (optional utility if needed later)
def encrypt_message(message):
    chacha = ChaCha20Poly1305(SECRET_KEY)
    nonce = os.urandom(12)
    encrypted = chacha.encrypt(nonce, message.encode(), None)
    return (nonce + encrypted).hex()

# Decrypt a message (optional utility if needed later)
def decrypt_message(hexdata):
    chacha = ChaCha20Poly1305(SECRET_KEY)
    data = bytes.fromhex(hexdata)
    nonce = data[:12]
    ciphertext = data[12:]
    decrypted = chacha.decrypt(nonce, ciphertext, None)
    return decrypted.decode()

# Route to receive encrypted message from client
@app.route('/send', methods=['POST'])
def send_message():
    data = request.get_json()
    encrypted_message = data.get('message')

    if not encrypted_message:
        return jsonify({"error": "No message provided"}), 400

    messages.append(encrypted_message)
    return jsonify({"status": "Message received"}), 200

# Route to retrieve all encrypted messages
@app.route('/receive', methods=['GET'])
def receive_messages():
    return jsonify({"messages": messages}), 200

# Health check (optional but good for Railway)
@app.route('/', methods=['GET'])
def home():
    return "Server is running!", 200

if __name__ == '__main__':
    # Railway automatically injects $PORT
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
