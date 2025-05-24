import argparse
import logging
import os
import pathlib
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Verifies digital signatures of files against a provided public key or certificate, ensuring authenticity and integrity."
    )

    # Required arguments
    parser.add_argument("file_path", help="Path to the file to verify.")
    parser.add_argument("signature_file", help="Path to the signature file.")
    parser.add_argument("public_key", help="Path to the public key or certificate file.")

    # Optional arguments
    parser.add_argument(
        "--hash_algorithm",
        default="sha256",
        choices=["sha256", "sha512"],
        help="Hash algorithm to use for verification (default: sha256).",
    )
    parser.add_argument(
        "--openssl_path",
        default="openssl",
        help="Path to the openssl executable (default: openssl).",
    )

    return parser

def verify_signature(file_path, signature_file, public_key, hash_algorithm, openssl_path):
    """
    Verifies the digital signature of a file.

    Args:
        file_path (str): Path to the file to verify.
        signature_file (str): Path to the signature file.
        public_key (str): Path to the public key or certificate file.
        hash_algorithm (str): Hash algorithm to use (sha256 or sha512).
        openssl_path (str): Path to the openssl executable.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Input validation
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        if not os.path.exists(signature_file):
            raise FileNotFoundError(f"Signature file not found: {signature_file}")
        if not os.path.exists(public_key):
            raise FileNotFoundError(f"Public key/certificate file not found: {public_key}")

        # Construct the openssl command
        cmd = [
            openssl_path,
            "dgst",
            "-verify",
            public_key,
            "-signature",
            signature_file,
            "-" + hash_algorithm,
            file_path,
        ]

        # Execute the command
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check the return code
        if process.returncode == 0:
            # Check the output for "Verified OK"
            if "Verified OK" in stdout.decode():
                logging.info("Signature verification successful.")
                return True
            else:
                logging.error(f"Signature verification failed. openssl output: {stdout.decode()}")
                return False
        else:
            logging.error(f"Signature verification failed with openssl error: {stderr.decode()}")
            return False

    except FileNotFoundError as e:
        logging.error(str(e))
        return False
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return False

def main():
    """
    Main function to parse arguments and verify the signature.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Verify the signature
    if verify_signature(args.file_path, args.signature_file, args.public_key, args.hash_algorithm, args.openssl_path):
        print("Signature is valid.")
    else:
        print("Signature is invalid.")
        sys.exit(1)  # Exit with an error code

if __name__ == "__main__":
    main()

# Usage examples:
#
# Example 1: Verify a file with a signature file and public key using the default sha256 algorithm:
# python main.py myfile.txt myfile.txt.sig public_key.pem
#
# Example 2: Verify a file with a signature file and public key using the sha512 algorithm:
# python main.py myfile.txt myfile.txt.sig public_key.pem --hash_algorithm sha512
#
# Example 3:  Specify the path to openssl:
# python main.py myfile.txt myfile.txt.sig public_key.pem --openssl_path /usr/local/bin/openssl

# Offensive Tool Steps:
# 1. Tamper with the file:  Modify the myfile.txt and attempt verification.  Observe failure.
# 2. Forge a signature:  Attempt to create a forged signature (without the private key) and verify.  Observe failure.
# 3. Key substitution:  Replace public_key.pem with a different, invalid key.  Observe failure.