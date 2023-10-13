#!/usr/bin/env python3
import subprocess
import os
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import tempfile

def fetch_ssl_info(domain):
    try:
        # Run OpenSSL command to fetch SSL certificate information
        command = f"echo | openssl s_client -connect {domain}:443 2>/dev/null | openssl x509 -text -noout"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            print("SSL Certificate Information:\n")
            print(result.stdout)
        else:
            print("An error occurred.")
            print(result.stderr)

    except Exception as e:
        print(f"An exception occurred: {e}")

def check_domain(domain):
    # Code to check the domain
    pass

def check_revocation(domain):
    # Code to check for revocation
    pass

def check_csr(csr_content):
    try:
        # Load the CSR
        csr = x509.load_pem_x509_csr(csr_content.encode(), default_backend())

        # Extract the subject details
        subject = csr.subject
        print(f"Subject: {subject}")

        # Extract and properly serialize the public key
        public_key = csr.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        print(f"\nPublic Key: \n {serialized_public_key}")

        # Extract the extensions
        extensions = csr.extensions

        # Subject Alternative Names
        try:
            san = extensions.get_extension_for_class(x509.SubjectAlternativeName)
            print(f"Subject Alternative Names: {san.value.get_values_for_type(x509.DNSName)}")
        except x509.ExtensionNotFound:
            print("No Subject Alternative Names found.")

    except Exception as e:
        print(f"An exception occurred: {e}")

def decode_cert(cert_content):
    try:
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_content.encode(), default_backend())

        # Extract the issuer details
        issuer = cert.issuer
        print(f"Issuer: {issuer}")

        # Extract the subject details
        subject = cert.subject
        print(f"Subject: {subject}")

        # Extract and properly serialize the public key
        public_key = cert.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        print(f"Public Key: {serialized_public_key}")

        # Extract the validity period
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        print(f"Valid From: {not_before}")
        print(f"Valid To: {not_after}")

        # Extract the extensions
        extensions = cert.extensions

        # Subject Alternative Names
        try:
            san = extensions.get_extension_for_class(x509.SubjectAlternativeName)
            print(f"Subject Alternative Names: {san.value.get_values_for_type(x509.DNSName)}")
        except x509.ExtensionNotFound:
            print("No Subject Alternative Names found.")

    except Exception as e:
        print(f"An exception occurred: {e}")

def read_file_content(file_path):
    with open(file_path, 'r') as f:
        return f.read()

def verify_cert_chain(chain_path):
    try:
        chain_content = read_file_content(chain_path)

        # Split the certificates and explicitly add back the '-----END CERTIFICATE-----' part
        raw_certs = chain_content.strip().split('-----END CERTIFICATE-----')
        certs = [x509.load_pem_x509_certificate((cert + '-----END CERTIFICATE-----').encode(), default_backend())
                 for cert in raw_certs if cert.strip()]


        for i in range(len(certs) - 1):
            issuer = certs[i].issuer
            subject = certs[i + 1].subject
            if issuer != subject:
                print(f"The issuer of certificate {i+1} does not match the subject of certificate {i+2}")
                return False
            print("Certificate chain is valid.")
        return True

    except Exception as e:
        print(f"An exception occurred: {e}")
        return False

def verify_key_certificate_match(private_key, certificate):

    # Extract the public key from the certificate
    public_key = certificate.public_key()

    # Generate some test data
    test_data = b'test_data_to_sign'

    try:
        # Sign the data with the private key
        signature = private_key.sign(
            test_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Verify the signature with the public key
        public_key.verify(
            signature,
            test_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("The private key matches the certificate.")
        return True
    except Exception as e:
        print(f"The private key does not match the certificate. Error: {e}")
        return False

def find_and_verify_files_in_folder(folder_path=None):
    if folder_path is None:
        folder_path = os.getcwd()

    all_files = os.listdir(folder_path)
    
    key_file = next((f for f in all_files if f.endswith('.key')), None)
    crt_file = next((f for f in all_files if f.endswith('.crt') and not f.endswith('_chain.crt')), None)
    chain_file = next((f for f in all_files if f.endswith('_chain.crt')), None)

    if not key_file or not crt_file or not chain_file:
        print("Could not find all necessary files (.key, .crt, _chain.crt)")
        return False

    with open(os.path.join(folder_path, key_file), 'rb') as f:
        key_content = f.read()
    with open(os.path.join(folder_path, crt_file), 'rb') as f:
        crt_content = f.read()
    with open(os.path.join(folder_path, chain_file), 'rb') as f:
        chain_content = f.read()
    private_key = serialization.load_pem_private_key(key_content, None, default_backend())
    certificate = x509.load_pem_x509_certificate(crt_content, default_backend())
    chain_content_str = chain_content.decode('utf-8')
    raw_certs = chain_content_str.strip().split('-----END CERTIFICATE-----')
    certificates = [cert + '-----END CERTIFICATE-----' for cert in raw_certs if cert.strip()]

    
    chain_certs = [x509.load_pem_x509_certificate((cert + '-----END CERTIFICATE-----').encode(), default_backend())
                 for cert in certificates if cert.strip()]

    # Verify private key matches the certificate
    try:
        verify_key_certificate_match(private_key, certificate)
    except:
        print("The private key does not match the certificate.")
        return False

    # Add the main certificate to the start of the chain
    chain_certs.insert(0, certificate)

    # Create a temporary file with the modified certificate chain
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_name = temp_file.name
        for cert in chain_certs:
            temp_file.write(cert.public_bytes(serialization.Encoding.PEM))

    # Now you can run your verify-chain function using the path to the temporary file.
    if not verify_cert_chain(temp_file_name):
        print("The certificate chain verification failed.")
        return False
    
    # Delete the temporary file
    os.remove(temp_file_name)

    print("All files match!")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSL and CSR checker tool.")
    parser.add_argument('--ssl-info', dest='ssl_info', type=str, help='Fetch SSL information for a domain')
    parser.add_argument('--check-domain', dest='check_domain', type=str, help='Check if SSL certificate is correctly installed for a domain')
    parser.add_argument('--check-revocation', dest='check_revocation', type=str, help='Check if SSL certificate is revoked')
    parser.add_argument('--check-csr', dest='check_csr', type=str, help='Check a CSR')
    parser.add_argument('--cert-decode', dest='cert_decode', type=str, help='Decode an SSL certificate (use triple quotes for multiline string)')
    parser.add_argument('--verify-chain', dest='verify_chain', type=str, help='Verify a certificate chain file')
    parser.add_argument('--match-files', action='store_true', help='Verify that the key, certificate, and chain files match')
    args = parser.parse_args()

    if args.ssl_info:
        fetch_ssl_info(args.ssl_info)
    if args.check_domain:
        check_domain(args.check_domain)
    if args.check_revocation:
        check_revocation(args.check_revocation)
    if args.check_csr:
        check_csr(args.check_csr)
    if args.cert_decode:
        decode_cert(args.cert_decode)
    if args.verify_chain:
        verify_cert_chain(args.verify_chain)
    if args.match_files:
        find_and_verify_files_in_folder()
