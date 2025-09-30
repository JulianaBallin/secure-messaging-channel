"""
rsa_manager.py
--------------

Implements RSA key generation, serialization, and management.  
This module handles asymmetric encryption tasks such as key pair creation and 
public/private key serialization for secure key exchange between users.

Functions:
    - generate_rsa_keys(): Generates a new RSA private/public key pair.
    - serialize_keys(private_key, public_key): Serializes keys into PEM format.
"""


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):
    """Serializa as chaves para salvar ou transmitir."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem
