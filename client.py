#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════╗
║       SECURE E2E ENCRYPTED CHAT CLIENT        ║
║         RSA-2048 + AES-256-GCM               ║
╚═══════════════════════════════════════════════╝

HANDSHAKE PROTOCOL
──────────────────
1.  Generate RSA-2048 keypair locally (private key NEVER leaves this process).
2.  Send public key + alias to server.
3.  Server swaps public keys with the other client.
4.  We (or peer) generate a random 256-bit AES key, encrypt it with the
    peer's RSA public key, and send ciphertext through server.
5.  Peer decrypts AES key with their private key.
6.  All subsequent messages use AES-256-GCM (nonce prepended).
"""

import socket
import threading
import json
import base64
import os
import sys
import signal
import getpass
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── ANSI Colors ────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

# ── Helpers ────────────────────────────────────

def ts():
    return datetime.now().strftime("%H:%M:%S")

def print_sys(msg):
    print(f"\r{DIM}[{ts()}]{RESET} {GREEN}{msg}{RESET}")

def print_err(msg):
    print(f"\r{DIM}[{ts()}]{RESET} {RED}[!] {msg}{RESET}")

def print_incoming(alias, msg):
    print(f"\r{DIM}[{ts()}]{RESET} {WHITE}{BOLD}{alias}{RESET}{WHITE}: {msg}{RESET}")

def print_own(msg):
    # Reprint own message above input line in cyan
    print(f"\r{DIM}[{ts()}]{RESET} {CYAN}{BOLD}You{RESET}{CYAN}: {msg}{RESET}")

def prompt():
    sys.stdout.write(f"{CYAN}> {RESET}")
    sys.stdout.flush()


def banner(host, port, alias):
    print(f"""
{GREEN}{BOLD}
╔══════════════════════════════════════════════════════╗
║       SECURE E2E ENCRYPTED CHAT — CLIENT            ║
║         RSA-2048 Handshake · AES-256-GCM            ║
╠══════════════════════════════════════════════════════╣
║  Alias  : {alias:<42}{GREEN}║
║  Server : {host}:{port:<37}{GREEN}║
║  Keys   : Generated locally, private key stays here ║
╚══════════════════════════════════════════════════════╝
{RESET}  {DIM}Type a message and press Enter.  /quit to exit.{RESET}
""")


# ── Crypto helpers ─────────────────────────────

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()

def serialize_pubkey(pub):
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def deserialize_pubkey(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())

def rsa_encrypt(pubkey, plaintext: bytes) -> bytes:
    return pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(privkey, ciphertext: bytes) -> bytes:
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct   # prepend nonce

def aes_decrypt(key: bytes, data: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce, ct = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


# ── Client ─────────────────────────────────────

class ChatClient:
    def __init__(self, host, port, alias):
        self.host = host
        self.port = port
        self.alias = alias
        self.sock = None
        self.buf = ""

        # RSA keypair (generated fresh every session)
        print_sys("Generating RSA-2048 keypair…")
        self.private_key, self.public_key = generate_rsa_keypair()
        print_sys("Keypair generated ✔")

        self.peer_pubkey = None     # RSA pubkey of our peer
        self.aes_key = None         # Shared AES-256 key
        self.peer_alias = "Peer"
        self.running = True
        self.handshake_done = False
        self.i_initiate_aes = False  # True if we send the AES key first

    # ── Network I/O ───────────────────────────────

    def send_packet(self, data: dict):
        raw = (json.dumps(data) + "\n").encode()
        self.sock.sendall(raw)

    def recv_packet(self) -> dict:
        while "\n" not in self.buf:
            chunk = self.sock.recv(65536).decode()
            if not chunk:
                raise ConnectionResetError("Server closed connection")
            self.buf += chunk
        line, self.buf = self.buf.split("\n", 1)
        return json.loads(line)

    # ── Handshake ─────────────────────────────────

    def do_handshake(self):
        """Phase 1: register and wait for peer's public key."""
        self.send_packet({
            "type": "register",
            "alias": self.alias,
            "pubkey": serialize_pubkey(self.public_key)
        })
        print_sys("Public key sent to server. Waiting for peer…")

    def handle_peer_pubkey(self, packet):
        """Phase 2: got peer's RSA public key from server.

        The server assigns exactly one client role='initiator' and the
        other role='receiver'.  Only the initiator generates and sends
        the AES key, preventing both sides from creating conflicting keys.
        """
        self.peer_pubkey = deserialize_pubkey(packet["pubkey"])
        self.peer_alias  = packet.get("peer", "Peer")
        role             = packet.get("role", "receiver")  # safe default: wait
        print_sys(f"Received {self.peer_alias}'s public key \u2714  [role: {role}]")

        if role == "initiator":
            self.i_initiate_aes = True
            self.initiate_aes_exchange()
        else:
            self.i_initiate_aes = False
            print_sys("Waiting for peer to complete AES key exchange\u2026")

    def initiate_aes_exchange(self):
        """Generate AES-256 key, encrypt with peer's RSA pubkey, send."""
        self.aes_key = os.urandom(32)   # 256 bits
        encrypted_key = rsa_encrypt(self.peer_pubkey, self.aes_key)
        self.send_packet({
            "type": "aes_key_exchange",
            "key_enc": base64.b64encode(encrypted_key).decode()
        })
        print_sys("AES key generated & sent (encrypted with peer's RSA key) ✔")
        self.handshake_done = True
        print_sys(f"{GREEN}{BOLD}Secure channel established with {self.peer_alias}! Start chatting.{RESET}")
        prompt()

    def handle_aes_key(self, packet):
        """Peer sent us an encrypted AES key — decrypt with our RSA private key."""
        # Update peer alias if the relay included it
        if packet.get("from"):
            self.peer_alias = packet["from"]
        encrypted_key = base64.b64decode(packet["key_enc"])
        self.aes_key = rsa_decrypt(self.private_key, encrypted_key)
        print_sys("Received & decrypted AES key \u2714")
        print_sys(f"{GREEN}{BOLD}Secure channel established with {self.peer_alias}! Start chatting.{RESET}")
        self.handshake_done = True
        prompt()

    # ── Receive loop (background thread) ──────────

    def receive_loop(self):
        try:
            while self.running:
                packet = self.recv_packet()
                ptype = packet.get("type")

                if ptype == "welcome":
                    print_sys(packet["msg"])

                elif ptype == "system":
                    print_sys(packet["msg"])
                    # If peer rejoined or left, reset handshake state
                    if "left" in packet["msg"]:
                        self.aes_key = None
                        self.handshake_done = False
                        self.peer_pubkey = None
                        print_sys("Peer disconnected. AES session invalidated.")
                    prompt()

                elif ptype == "peer_pubkey":
                    self.handle_peer_pubkey(packet)

                elif ptype == "aes_key_exchange":
                    self.handle_aes_key(packet)
                    prompt()

                elif ptype == "message":
                    if not self.aes_key:
                        print_err("Received message before AES key exchange — ignoring.")
                        continue
                    try:
                        raw = base64.b64decode(packet["ciphertext"])
                        plaintext = aes_decrypt(self.aes_key, raw)
                        sender = packet.get("from", self.peer_alias)
                        print_incoming(sender, plaintext)
                    except Exception as e:
                        print_err(f"Decryption failed: {e}")
                    prompt()

                else:
                    print_err(f"Unknown packet type: {ptype}")

        except (ConnectionResetError, OSError):
            if self.running:
                print_err("Lost connection to server.")
                self.running = False

    # ── Send ──────────────────────────────────────

    def send_message(self, text: str):
        if not self.handshake_done or not self.aes_key:
            print_err("Secure channel not yet established — please wait for peer.")
            return
        ciphertext = aes_encrypt(self.aes_key, text)
        self.send_packet({
            "type": "message",
            "ciphertext": base64.b64encode(ciphertext).decode()
        })
        print_own(text)

    # ── Main ──────────────────────────────────────

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print_err(f"Cannot connect to {self.host}:{self.port} — is server.py running?")
            sys.exit(1)

        banner(self.host, self.port, self.alias)

        self.do_handshake()

        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        recv_thread.start()

        def shutdown(sig, frame):
            self.quit()

        signal.signal(signal.SIGINT, shutdown)

        # ── Input loop ────────────────────────────
        try:
            while self.running:
                prompt()
                try:
                    line = input()
                except EOFError:
                    break

                if not line.strip():
                    continue

                if line.strip().lower() == "/quit":
                    self.quit()
                    break

                self.send_message(line.strip())

        except KeyboardInterrupt:
            pass

        self.quit()

    def quit(self):
        if not self.running:
            return
        self.running = False
        print_sys("Disconnecting…")
        try:
            self.send_packet({"type": "quit"})
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        print_sys("Goodbye. 👋")
        sys.exit(0)


# ── Entry point ────────────────────────────────

if __name__ == "__main__":
    print(f"\n{GREEN}{BOLD}  SECURE E2E CHAT — CLIENT SETUP{RESET}\n")

    host = input(f"  {DIM}Server host [{SERVER_HOST}]: {RESET}").strip() or SERVER_HOST
    port_str = input(f"  {DIM}Server port [{SERVER_PORT}]: {RESET}").strip()
    port = int(port_str) if port_str.isdigit() else SERVER_PORT
    alias = input(f"  {DIM}Your alias: {RESET}").strip() or f"user_{os.getpid()}"

    client = ChatClient(host, port, alias)
    client.run()

