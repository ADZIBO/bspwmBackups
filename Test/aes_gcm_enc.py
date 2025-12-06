#!/usr/bin/env python3

import os
import argparse
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

def derive_key(password: bytes, salt: bytes, iterations=1000000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password)

def encrypt_file(input_path, output_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    with open(output_path, "wb") as f:
        f.write(salt + iv + tag + ciphertext)

    print(f"[+] Archivo cifrado: {output_path}")

def decrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    ciphertext = data[44:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        print(f"[!] Error: el archivo puede haber sido modificado o la contraseña es incorrecta.")
        return

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Archivo descifrado: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM + PBKDF2 en Python")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Cifrar archivo")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Descifrar archivo")
    parser.add_argument("-i", "--input", required=True, help="Archivo de entrada")
    parser.add_argument("-o", "--output", required=True, help="Archivo de salida")

    args = parser.parse_args()

    password = getpass("Contraseña: ").encode()

    if args.encrypt:
        encrypt_file(args.input, args.output, password)
    elif args.decrypt:
        decrypt_file(args.input, args.output, password)
    else:
        print("Debes usar -e (encrypt) o -d (decrypt)")

if __name__ == "__main__":
    main()
