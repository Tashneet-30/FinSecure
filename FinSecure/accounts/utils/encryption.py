from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_value(value: str, key: str) -> str:
    if value is None:
        return None
    f = Fernet(key)
    return f.encrypt(value.encode()).decode()

def decrypt_value(value: str, key: str) -> str:
    if value is None:
        return None
    f = Fernet(key)
    return f.decrypt(value.encode()).decode()