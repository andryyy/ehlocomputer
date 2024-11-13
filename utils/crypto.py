import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from functools import lru_cache
from pydantic import validate_call


__all__ = [
    "InvalidToken",
    "fernet_encrypt",
    "fernet_decrypt",
    "aes_cbc_encrypt",
    "aes_cbc_decrypt",
]


def sha256_filedigest(filename: str):
    with open(filename, "rb", buffering=0) as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


@validate_call
def aes_cbc_encrypt(
    data: str, code: str, iv: bytes = os.urandom(16), salt: bytes = os.urandom(16)
) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(code.encode("utf-8"))
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode("utf-8")) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + ciphertext


@lru_cache
@validate_call
def aes_cbc_decrypt(data: bytes, code: str) -> str:
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(code.encode("utf-8"))
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode(encoding="utf-8")


@validate_call
def fernet_encrypt(data: str, code: str, salt: bytes = os.urandom(16)) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    fernet = Fernet(
        base64.urlsafe_b64encode(kdf.derive(code.encode("utf-8"))),
    )
    return base64.urlsafe_b64encode(salt + fernet.encrypt(data.encode("utf-8")))


@lru_cache
@validate_call
def fernet_decrypt(data: str, code: str) -> str:
    data = base64.urlsafe_b64decode(data)
    salt = data[:16]
    encrypted_data = data[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(code.encode("utf-8"))))
    return fernet.decrypt(encrypted_data).decode(encoding="utf-8")
