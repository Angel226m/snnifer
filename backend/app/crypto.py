import bcrypt
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import os

# ============= PASSWORD ENCRYPTION (bcrypt) =============

def hash_password(password: str, rounds: int = 5) -> str:
    """Hash password using bcrypt with specified rounds."""
    salt = bcrypt.gensalt(rounds=rounds)
    password_hash = bcrypt.hashpw(password.encode(), salt)
    return password_hash.decode()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode(), password_hash.encode())

# ============= RSA-256 ENCRYPTION (for transit) =============

def generate_rsa_keypair():
    """Generate RSA-256 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(data: dict, public_key) -> str:
    """Encrypt data with RSA public key."""
    json_data = json.dumps(data).encode()
    encrypted = public_key.encrypt(
        json_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(encrypted_data: str, private_key) -> dict:
    """Decrypt data with RSA private key."""
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return json.loads(decrypted.decode())

# ============= CHACHA20-POLY1305 ENCRYPTION =============

def chacha20_encrypt(data: dict, key: bytes = None) -> str:
    """Encrypt data with ChaCha20-Poly1305."""
    if key is None:
        key = os.urandom(32)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    plaintext = json.dumps(data).encode()
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    result = base64.b64encode(nonce + ciphertext).decode()
    return result, key.hex()

def chacha20_decrypt(encrypted_data: str, key_hex: str) -> dict:
    """Decrypt data with ChaCha20-Poly1305."""
    key = bytes.fromhex(key_hex)
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode())

def chacha20_encrypt_transit(data: dict) -> str:
    """Encrypt data for transit (includes key in result)."""
    encrypted, key_hex = chacha20_encrypt(data)
    # Format: key:ciphertext for easy transit
    return f"{key_hex}:{encrypted}"

def chacha20_decrypt_transit(transit_data: str) -> dict:
    """Decrypt transit data."""
    key_hex, encrypted = transit_data.split(":", 1)
    return chacha20_decrypt(encrypted, key_hex)

# ============= AES-256-GCM ENCRYPTION =============

def aes256_encrypt(data: dict, key: bytes = None) -> str:
    """Encrypt data with AES-256-GCM."""
    if key is None:
        key = os.urandom(32)

    nonce = os.urandom(12)
    cipher = AESGCM(key)
    plaintext = json.dumps(data).encode()
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    result = base64.b64encode(nonce + ciphertext).decode()
    return result, key.hex()

def aes256_decrypt(encrypted_data: str, key_hex: str) -> dict:
    """Decrypt data with AES-256-GCM."""
    key = bytes.fromhex(key_hex)
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode())

def aes256_encrypt_transit(data: dict) -> str:
    """Encrypt data for transit (includes key in result)."""
    encrypted, key_hex = aes256_encrypt(data)
    # Format: key:ciphertext for easy transit
    return f"{key_hex}:{encrypted}"

def aes256_decrypt_transit(transit_data: str) -> dict:
    """Decrypt transit data."""
    key_hex, encrypted = transit_data.split(":", 1)
    return aes256_decrypt(encrypted, key_hex)

# ============= FERNET ENCRYPTION (symmetric) =============

def fernet_encrypt(data: dict, key: bytes = None) -> str:
    """Encrypt data with Fernet."""
    if key is None:
        key = Fernet.generate_key()

    f = Fernet(key)
    plaintext = json.dumps(data).encode()
    ciphertext = f.encrypt(plaintext)

    result = base64.b64encode(ciphertext).decode()
    return result, key.decode()

def fernet_decrypt(encrypted_data: str, key: str) -> dict:
    """Decrypt data with Fernet."""
    f = Fernet(key.encode())
    ciphertext = base64.b64decode(encrypted_data.encode())
    plaintext = f.decrypt(ciphertext)

    return json.loads(plaintext.decode())

def fernet_encrypt_transit(data: dict) -> str:
    """Encrypt data for transit (includes key in result)."""
    encrypted, key = fernet_encrypt(data)
    # Format: key:ciphertext for easy transit
    return f"{key}:{encrypted}"

def fernet_decrypt_transit(transit_data: str) -> dict:
    """Decrypt transit data."""
    key, encrypted = transit_data.split(":", 1)
    return fernet_decrypt(encrypted, key)

# ============= ENCRYPTION DISPATCHER =============

ENCRYPTION_METHODS = {
    "aes256gcm": {
        "encrypt": aes256_encrypt_transit,
        "decrypt": aes256_decrypt_transit,
    },
    "chacha20poly1305": {
        "encrypt": chacha20_encrypt_transit,
        "decrypt": chacha20_decrypt_transit,
    },
    "fernet": {
        "encrypt": fernet_encrypt_transit,
        "decrypt": fernet_decrypt_transit,
    },
}

def encrypt_data(data: dict, method: str = "fernet") -> str:
    """Encrypt data using specified method."""
    method_lower = method.lower().replace("-", "")
    if method_lower not in ENCRYPTION_METHODS:
        raise ValueError(f"Unknown encryption method: {method}")
    return ENCRYPTION_METHODS[method_lower]["encrypt"](data)

def decrypt_data(encrypted_data: str, method: str = "fernet") -> dict:
    """Decrypt data using specified method."""
    method_lower = method.lower().replace("-", "")
    if method_lower not in ENCRYPTION_METHODS:
        raise ValueError(f"Unknown encryption method: {method}")
    return ENCRYPTION_METHODS[method_lower]["decrypt"](encrypted_data)
