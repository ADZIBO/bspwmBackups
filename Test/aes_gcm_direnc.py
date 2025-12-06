#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aes_gcm_direnc.py
Cifrado y descifrado recursivo de directorios completos usando AES-256-GCM + PBKDF2-HMAC-SHA256.

Formato de cada archivo cifrado:
    [16B salt][12B iv][16B tag][ciphertext...]

Autor: [ZIBERSEC]
"""

import os
import argparse
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CHUNK_SIZE = 64 * 1024  # 64 KiB
ENCRYPTED_EXT = ".enc"  # extensión añadida a archivos cifrados


def derive_key(password: bytes, salt: bytes, iterations=1_000_000) -> bytes:
    """Deriva una clave AES-256 a partir de una contraseña usando PBKDF2-HMAC-SHA256."""
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password)


def encrypt_file(input_path: str, output_path: str, password: bytes):
    """Cifra un archivo usando AES-256-GCM."""
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(salt + iv)
        while chunk := f_in.read(CHUNK_SIZE):
            f_out.write(encryptor.update(chunk))
        encryptor.finalize()
        f_out.write(encryptor.tag)

    print(f"[+] Cifrado: {input_path} → {output_path}")


def decrypt_file(input_path: str, output_path: str, password: bytes):
    """Descifra un archivo cifrado con AES-256-GCM."""
    file_size = os.path.getsize(input_path)
    if file_size < 44:
        print(f"[!] Archivo inválido: {input_path}")
        return

    with open(input_path, "rb") as f_in:
        salt = f_in.read(16)
        iv = f_in.read(12)
        tag_position = file_size - 16
        ciphertext_length = tag_position - 28
        key = derive_key(password, salt)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).decryptor()
        bytes_remaining = ciphertext_length

        with open(output_path, "wb") as f_out:
            while bytes_remaining > 0:
                chunk = f_in.read(min(CHUNK_SIZE, bytes_remaining))
                if not chunk:
                    break
                f_out.write(decryptor.update(chunk))
                bytes_remaining -= len(chunk)

            f_in.seek(tag_position)
            tag = f_in.read(16)
            decryptor._ctx.set_tag(tag)
            try:
                decryptor.finalize()
            except Exception:
                print(f"[!] Error: contraseña incorrecta o archivo dañado ({input_path})")
                f_out.close()
                os.remove(output_path)
                return

    print(f"[+] Descifrado: {input_path} → {output_path}")


def process_directory(input_dir: str, output_dir: str, password: bytes, encrypt=True):
    """Procesa todos los archivos del directorio de forma recursiva."""
    for root, _, files in os.walk(input_dir):
        rel_path = os.path.relpath(root, input_dir)
        target_dir = os.path.join(output_dir, rel_path)
        os.makedirs(target_dir, exist_ok=True)

        for filename in files:
            in_path = os.path.join(root, filename)

            if encrypt:
                # Evitar cifrar archivos ya cifrados
                if filename.endswith(ENCRYPTED_EXT):
                    continue
                out_path = os.path.join(target_dir, filename + ENCRYPTED_EXT)
                encrypt_file(in_path, out_path, password)
            else:
                # Solo descifrar archivos .enc
                if not filename.endswith(ENCRYPTED_EXT):
                    continue
                out_name = filename[:-len(ENCRYPTED_EXT)]
                out_path = os.path.join(target_dir, out_name)
                decrypt_file(in_path, out_path, password)


def main():
    parser = argparse.ArgumentParser(description="Cifrar/Descifrar directorios con AES-256-GCM")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Cifrar un directorio completo")
    group.add_argument("-d", "--decrypt", action="store_true", help="Descifrar un directorio completo")
    parser.add_argument("-i", "--input", required=True, help="Directorio de entrada")
    parser.add_argument("-o", "--output", required=True, help="Directorio de salida")

    args = parser.parse_args()
    if not os.path.isdir(args.input):
        print("[!] La ruta de entrada debe ser un directorio válido.")
        return

    password = getpass("Contraseña: ").encode()

    if args.encrypt:
        confirm = getpass("Confirmar contraseña: ").encode()
        if password != confirm:
            print("[!] Las contraseñas no coinciden.")
            return
        process_directory(args.input, args.output, password, encrypt=True)

    elif args.decrypt:
        process_directory(args.input, args.output, password, encrypt=False)


if __name__ == "__main__":
    main()
