from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os


class OpenSSLCertHandler:
    def __init__(self, cert_path, key_path):
        self.cert_path = cert_path
        self.key_path = key_path
        self.certificate = None
        self.private_key = None
        self.load_credentials()

    def load_credentials(self):
        """Load certificate and private key from files"""
        try:

            print(f"Loading certificate from: {self.cert_path}")
            print(f"Loading private key from: {self.key_path}")
            # Load certificate
            with open(self.cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                self.certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Load private key
            with open(self.key_path, 'rb') as key_file:
                key_data = key_file.read()
                self.private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            raise Exception(f"Failed to load certificate or key: {str(e)}")

    def sign_data(self, data):
        """Sign data using the private key"""
        if not self.private_key:
            raise Exception("Private key not loaded")

        print(f"Signing data of length: {len(data)}")
        print(f"First few bytes of data to sign: {data[:32].hex()}")

        try:
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"Generated signature length: {len(signature)}")
            print(f"First few bytes of signature: {signature[:32].hex()}")
            return signature
        except Exception as e:
            print(f"Signing error: {str(e)}")
            raise

    def verify_signature(self, signature, data):
        """Verify signature using the certificate's public key"""
        if not self.certificate:
            raise Exception("Certificate not loaded")

        print(f"Verifying signature of length: {len(signature)}")
        print(f"Against data of length: {len(data)}")
        print(f"First few bytes of data to verify: {data[:32].hex()}")
        print(f"First few bytes of signature: {signature[:32].hex()}")

        try:
            self.certificate.public_key().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False

    def get_certificate_data(self):
        """Get certificate in PEM format for transmission"""
        if not self.certificate:
            raise Exception("Certificate not loaded")

        return self.certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )