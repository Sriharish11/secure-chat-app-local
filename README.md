# Secure Chat App (Local) 🛡️💬

A terminal-based, end-to-end encrypted (E2EE) chat application built for Linux. This project utilizes a Client-Server architecture with hybrid encryption to ensure that messages remain private, even from the server itself.

## 🚀 Features
- **Full CLI Control:** Lightweight and designed for terminal enthusiasts.
- **End-to-End Encryption (E2EE):** Uses **RSA-2048** for secure key exchange and **AES-GCM** for high-speed message encryption.
- **Multi-Client Support:** Built with Python's `threading` and `socket` libraries to handle multiple simultaneous connections.
- **Hacker-Style Interface:** Color-coded messages using ANSI escape sequences for better readability (Green for system, Cyan for you, White for others).
- **Privacy First:** The server acts as a blind relay and never has access to the private keys or decrypted message content.

## 🔒 Security Architecture
The application uses a **Hybrid Encryption** workflow:
1. **Handshake:** On startup, each client generates a unique RSA-2048 key pair.
2. **Key Exchange:** Public keys are shared via the server.
3. **Symmetric Encryption:** A unique AES session key is generated and shared securely using the recipient's RSA Public Key.
4. **Communication:** All chat data is encrypted via AES-GCM before leaving the client's machine.

## 🛠️ Prerequisites
- Linux (Optimized for Kali Linux/Ubuntu)
- Python 3.x
- `cryptography` library

Install dependencies:
```bash
pip install cryptography
