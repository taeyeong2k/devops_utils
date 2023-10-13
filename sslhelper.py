#!/usr/bin/env python3
import subprocess
import re
import os
import argparse
import shutil
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
        with open("temp_csr.pem", "w") as f:
            f.write(csr_content)

        # Get all CSR details in text format
        csr_text = subprocess.getoutput("openssl req -in temp_csr.pem -text -noout")

        # Define regex patterns for extracting information
        subject_pattern = r"Subject: (.+)"
        public_key_pattern = r"Public Key Algorithm: (.+)"
        san_pattern = r"X509v3 Subject Alternative Name: \n +([^\n]+)"

        # Extract details using regex
        subject = re.search(subject_pattern, csr_text).group(1)
        public_key_algo = re.search(public_key_pattern, csr_text).group(1)
        san = re.search(san_pattern, csr_text).group(1) if re.search(san_pattern, csr_text) else "No Subject Alternative Names found."

        # Print extracted details
        print(f"Subject: {subject}")
        print(f"Public Key Algorithm: {public_key_algo}")
        print(f"Subject Alternative Names: {san}")

    except Exception as e:
        print(f"An exception occurred: {e}")

    finally:
        subprocess.run(["rm", "temp_csr.pem"])

def decode_cert(cert_content):
    try:
        with open("temp_cert.pem", "w") as f:
            f.write(cert_content)

        # Get all certificate details in text format
        cert_text = subprocess.getoutput("openssl x509 -in temp_cert.pem -text -noout")

        # Define regex patterns for extracting information
        issuer_pattern = r"Issuer: (.+)"
        subject_pattern = r"Subject: (.+)"
        validity_pattern = r"Not Before: (.+), Not After : (.+)"
        public_key_pattern = r"Public Key Algorithm: (.+)"
        san_pattern = r"X509v3 Subject Alternative Name: \n +([^\n]+)"

        # Extract details using regex
        issuer = re.search(issuer_pattern, cert_text).group(1)
        subject = re.search(subject_pattern, cert_text).group(1)
        not_before, not_after = re.search(validity_pattern, cert_text).groups()
        public_key_algo = re.search(public_key_pattern, cert_text).group(1)
        san = re.search(san_pattern, cert_text).group(1) if re.search(san_pattern, cert_text) else "No Subject Alternative Names found."

        # Print extracted details
        print(f"Issuer: {issuer}")
        print(f"Subject: {subject}")
        print(f"Public Key Algorithm: {public_key_algo}")
        print(f"Valid From: {not_before}")
        print(f"Valid To: {not_after}")
        print(f"Subject Alternative Names: {san}")

    except Exception as e:
        print(f"An exception occurred: {e}")

    finally:
        subprocess.run(["rm", "temp_cert.pem"])

def read_file_content(file_path):
    with open(file_path, 'r') as f:
        return f.read()

def verify_cert_chain(chain_path):
    try:
        # Check if the 'temp_chain.pem' file already exists; if so, remove it
        if shutil.which("temp_chain.pem"):
            subprocess.run(["rm", "temp_chain.pem"])

        # Copy the original chain file to a temporary file for manipulation
        shutil.copy(chain_path, "temp_chain.pem")

        # Verify the certificate chain using OpenSSL
        result = subprocess.run(["openssl", "verify", "-CAfile", "temp_chain.pem", "temp_chain.pem"], capture_output=True, text=True)

        if "OK" in result.stdout:
            print("Certificate chain is valid.")
            return True
        else:
            print(f"Certificate chain is invalid: {result.stderr}")
            return False

    except Exception as e:
        print(f"An exception occurred: {e}")
        return False

    finally:
        subprocess.run(["rm", "temp_chain.pem"])

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
