# rsa_key_manager.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class RSAKeyManager:
    @staticmethod
    def generate_4096_rsa_key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        public_key = private_key.public_key()

        # Exporting keys
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

    @staticmethod
    def upgrade_rsa_key_size():
        private_key, public_key = RSAKeyManager.generate_4096_rsa_key()
        print("New 4096-bit RSA Key generated.")
        print("Private Key:\n", private_key.decode('utf-8'))
        print("Public Key:\n", public_key.decode('utf-8'))
