#"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
#raise NotImplementedError("students: implement cert issuance")

#
#Issue server/client certificate signed by Root CA (SAN=DNSName(CN)).
#mplements assignment requirement for certificate issuance.
#Adapted from cryptography.io X.509 examples.


import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def issue_certificate(ca_name: str, cert_name: str, cert_type: str, output_dir: str = "certs"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Load CA Private Key and certificate
    ca_key_path = os.path.join(output_dir, f"{ca_name}_ca_key.pem")
    ca_cert_path = os.path.join(output_dir, f"{ca_name}_ca_cert.pem")

    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        raise FileNotFoundError("CA key or certificate file not found. Please generate the CA first.")
    
    with open(ca_key_path, "rb") as key_file:
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open(ca_cert_path, "rb") as cert_file:
        ca_certificate = x509.load_pem_x509_certificate(
            cert_file.read(), 
            backend=default_backend()
        )
    
    # Generate RSA Private Key for this entity (server/client)
    entity_rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Build X.509 certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ICT"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, cert_name),
    ])

    # Build and sign X.509 certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(entity_rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cert_name)]),
            critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if cert_type == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        ) 
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False)
    )

    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    # Write entity Private Key and Certificate to PEM files
    entity_key_path = os.path.join(output_dir, f"{cert_name}_key.pem")
    entit_cert_path = os.path.join(output_dir, f"{cert_name}_cert.pem")

    with open(entity_key_path, "wb") as key_file:
        key_file.write(
            entity_rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    with open(entit_cert_path, "wb") as cert_file:
        cert_file.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )

    print(f"{cert_type.capitalize()} certificate issued successfully!")
    print(f"Private Key: {entity_key_path}")
    print(f"Certificate: {entit_cert_path}")


############################
# DRIVER CODE - COMMENT THIS OUT WHEN TESTING FULL APP
############################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue server/client certificate signed by Root CA.")
    parser.add_argument("ca_name", type=str, help="Name of the Root CA (used in file names).")
    parser.add_argument("cert_name", type=str, help="Common Name (CN) for the new certificate.")
    parser.add_argument("cert_type", type=str, choices=["server", "client"], help="Type of certificate to issue (server/client).")
    parser.add_argument("--output_dir", type=str, default="certs", help="Directory to save the issued certificate and key.")
    
    args = parser.parse_args()
    
    issue_certificate(args.ca_name, args.cert_name, args.cert_type, args.output_dir)

############################
# End of DRIVER CODE
############################
# to run from command line:
# python scripts/gen_cert.py MyRootCA myserver.example.com server --output_dir certs
# python scripts/gen_ca.py --ca-name MyRootCA --output-dir certs
# python scripts/gen_cert.py MyRootCA client.example.com client --output_dir certs
# python scripts/gen_cert.py MyRootCA myserver.example.com server --output_dir certs