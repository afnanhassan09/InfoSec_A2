"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def sign_data(private_key_pem: str, data: bytes) -> bytes:
    
    if isinstance(private_key_pem, str):
        pem_bytes = private_key_pem.encode("utf-8")
    else:
        pem_bytes = private_key_pem

    private_key = serialization.load_pem_private_key(
        pem_bytes, password=None, backend=default_backend()
    )

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature

def verify_signature(public_key_pem: str, data: bytes, signature: bytes) -> bool:
    
    if isinstance(public_key_pem, str):
        pub_bytes = public_key_pem.encode("utf-8")
    else:
        pub_bytes = public_key_pem

    public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    data = b"Hello, this is a test message."

    signature = sign_data(private_key_pem, data)
    print("Signature:", signature.hex())

    is_valid = verify_signature(public_key_pem, data, signature)
    print("Is the signature valid?", is_valid)

# end of driver code #
#######################
# cli commands to run the test:
# python app/crypto/sign.py