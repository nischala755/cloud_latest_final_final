import os
import base64
import hashlib
import random
import string
import time
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import numpy as np

# Determine the best encryption method based on file characteristics
def determine_encryption_method(file_data, file_type):
    file_size = len(file_data)
    
    # Decision logic for encryption method
    if file_size < 1024 * 1024:  # Less than 1MB
        return "AES-256", "Small file size, symmetric encryption is efficient"
    elif file_type in ['.txt', '.csv', '.json']:
        return "RSA-2048", "Text-based file, asymmetric encryption provides better security"
    elif file_type in ['.jpg', '.png', '.gif']:
        return "AES-256-GCM", "Image file, authenticated encryption protects integrity"
    elif file_type in ['.pdf', '.docx']:
        return "Hybrid (RSA+AES)", "Document file, hybrid encryption balances security and performance"
    else:
        return "Quantum-Resistant(NTRU+Kyber)", "Unknown file type, using strongest encryption method"

# Generate encryption key
def generate_key(entropy_pool=None):
    # Use entropy pool if available
    if entropy_pool and len(entropy_pool) > 0:
        seed = ''.join(entropy_pool[-10:])
        random.seed(hashlib.sha256(seed.encode()).digest())
    
    # Generate a random key
    key = Fernet.generate_key()
    return key

# Simulate quantum-resistant key generation
def simulate_quantum_key(strength=256):
    # Simulate a quantum-resistant key generation process
    # This is a simulation and not actual quantum-resistant cryptography
    
    # Simulate quantum noise
    quantum_noise = np.random.normal(0, 1, strength // 8)
    
    # Convert to bytes
    key_bytes = bytearray()
    for value in quantum_noise:
        # Scale to 0-255 range
        byte_val = int((value + 4) * 32) % 256
        key_bytes.append(byte_val)
    
    # Ensure key is exactly the right length
    while len(key_bytes) < strength // 8:
        key_bytes.append(random.randint(0, 255))
    
    # Convert to base64 for storage
    return base64.b64encode(bytes(key_bytes)[:strength // 8])

# Encrypt file using the determined method
def encrypt_file(file_data, method, key=None):
    if key is None:
        key = generate_key()
    
    if method == "AES-256":
        # Use Fernet (AES-128-CBC with PKCS7 padding and HMAC)
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)
        return encrypted_data, key
    
    elif method == "RSA-2048":
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Encrypt with RSA (for small files only)
        encrypted_data = public_key.encrypt(
            file_data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Serialize private key for storage
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return encrypted_data, pem
    
    elif method == "AES-256-GCM":
        # Generate a random 96-bit IV
        iv = os.urandom(12)
        
        # Create an encryptor object
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        ).encryptor()
        
        # Encrypt the plaintext
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        
        # Get the tag
        tag = encryptor.tag
        
        # Return IV + tag + ciphertext
        return iv + tag + ciphertext, key
    
    elif method == "Hybrid (RSA+AES)":
        # Generate AES key
        aes_key = os.urandom(32)
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encrypt file data with AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Serialize private key
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Combine everything
        result = {
            "method": "hybrid",
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "encrypted_data": base64.b64encode(encrypted_data).decode()
        }
        
        return json.dumps(result).encode(), pem
    
    elif method == "Quantum-Resistant NTRU+Kyber":
        # Simulate quantum-resistant encryption (this is just a simulation)
        quantum_key = simulate_quantum_key()
        
        # Use AES as a stand-in for a quantum-resistant algorithm
        f = Fernet(quantum_key)
        encrypted_data = f.encrypt(file_data)
        
        # Add metadata to indicate this is "quantum-resistant"
        result = {
            "method": "quantum-resistant",
            "encrypted_data": base64.b64encode(encrypted_data).decode()
        }
        
        return json.dumps(result).encode(), quantum_key
    
    else:
        # Default to AES-256
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)
        return encrypted_data, key

# Decrypt file
def decrypt_file(encrypted_data, method, key, password=None):
    try:
        if method == "AES-256":
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            return decrypted_data
        
        elif method == "RSA-2048":
            # Load private key
            private_key = serialization.load_pem_private_key(
                key,
                password=None
            )
            
            # Decrypt with RSA
            decrypted_data = private_key.decrypt(
                encrypted_data,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted_data
        
        elif method == "AES-256-GCM":
            # Extract IV, tag, and ciphertext
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create a decryptor object
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag)
            ).decryptor()
            
            # Decrypt the ciphertext
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted_data
        
        elif method == "Hybrid (RSA+AES)":
            # Parse the encrypted data
            data = json.loads(encrypted_data)
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                key,
                password=None
            )
            
            # Decrypt AES key with RSA
            encrypted_aes_key = base64.b64decode(data["encrypted_aes_key"])
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file data with AES
            iv = base64.b64decode(data["iv"])
            encrypted_data = base64.b64decode(data["encrypted_data"])
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad the data
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            
            return decrypted_data
        
        elif method == "Quantum-Resistant NTRU+KYBER":
            # Parse the encrypted data
            data = json.loads(encrypted_data)
            
            # Decrypt with Fernet (simulating quantum-resistant decryption)
            encrypted_data = base64.b64decode(data["encrypted_data"])
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
            return decrypted_data
        
        else:
            # Default to AES-256
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            return decrypted_data
    
    except Exception as e:
        print(f"Decryption error: {e}")
        return None