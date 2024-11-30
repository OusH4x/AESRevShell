#!/usr/bin/env python3

import socket
import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

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

def start_server(ip, port):
    key = os.urandom(32)
    iv = os.urandom(16)
    print(f"[*] AES Key: {key.hex()}")
    print(f"[*] AES IV: {iv.hex()}")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1)
    print(f"[*] Listening on {ip}:{port}")
    client_socket, client_address = server.accept()
    print(f"[*] Connection established with {client_address}")
    try:
        client_socket.send(b"KEY_CHECK")
        client_key_iv = client_socket.recv(1024)
        if client_key_iv != key + iv:
            print("[!] Client provided incorrect key/IV. Closing connection.")
            client_socket.close()
            return
        print("[*] Client key/IV validated. Communication started.")
        while True:
            command = input("\n[Server] Enter command: ").strip()
            if command.lower() == "exit":
                encrypted_command = aes_encrypt(command.encode('utf-8'), key, iv)
                client_socket.send(encrypted_command)
                client_socket.close()
                print("[*] Connection closed.")
                break
            encrypted_command = aes_encrypt(command.encode('utf-8'), key, iv)
            client_socket.send(encrypted_command)
            encrypted_response = client_socket.recv(4096)
            if not encrypted_response:
                break
            response = aes_decrypt(encrypted_response, key, iv).decode('utf-8')
            print(f"\n[Client]: {response}")
    except Exception as e:
        print(f"[!] Error: {e}")
        client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", required=True, help="IP address to bind to")
    parser.add_argument("-p", "--port", required=True, type=int, help="Port to bind to")
    args = parser.parse_args()
    start_server(args.ip, args.port)
