import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import validate_call


@validate_call
def rsa_generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key_pem.decode("utf-8"), public_key_pem.decode("utf-8")


@validate_call
def rsa_private_key_from_pem(pem_data):
    return serialization.load_pem_private_key(
        key_file.read(), password=None, backend=default_backend()
    )


@validate_call
def rsa_public_key_from_pem(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


@validate_call
def rsa_encrypt(data, pem_pubkey):
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


@validate_call
def rsa_decrypt(data, pem_privkey):
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
