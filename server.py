#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════╗
║         SECURE E2E ENCRYPTED CHAT SERVER      ║
║              [ Relay Only Mode ]              ║
╚═══════════════════════════════════════════════╝
The server NEVER sees decrypted messages or private keys.
It only relays encrypted data between clients.
"""

import socket
import threading
import json
import base64
import sys
import signal
from datetime import datetime

# ── ANSI Colors ────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

HOST = "0.0.0.0"
PORT = 9999

def banner():
    print(f"""
{GREEN}{BOLD}
╔══════════════════════════════════════════════════════╗
║        SECURE E2E ENCRYPTED CHAT — SERVER           ║
║                 [ Relay Mode ]                      ║
╠══════════════════════════════════════════════════════╣
║  {DIM}Messages are end-to-end encrypted.               {GREEN}║
║  {DIM}This server cannot read any communications.      {GREEN}║
╚══════════════════════════════════════════════════════╝
{RESET}""")

def log(msg, color=GREEN):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {color}{msg}{RESET}")


class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}       # socket -> {"alias": str, "pubkey": str}
        self.lock = threading.Lock()
        self.server_socket = None

    def broadcast(self, data: dict, exclude=None):
        """Send a JSON packet to all connected clients except `exclude`."""
        raw = (json.dumps(data) + "\n").encode()
        with self.lock:
            targets = [s for s in self.clients if s is not exclude]
        for sock in targets:
            try:
                sock.sendall(raw)
            except Exception:
                pass

    def send_to(self, sock, data: dict):
        raw = (json.dumps(data) + "\n").encode()
        try:
            sock.sendall(raw)
        except Exception as e:
            log(f"Send error: {e}", RED)

    def relay_pubkeys(self):
        """When exactly 2 clients are connected, exchange their public keys.
        
        Client A (first to connect) gets role='receiver' — it waits for the AES key.
        Client B (second to connect) gets role='initiator' — it generates & sends the AES key.
        This guarantees exactly ONE AES key is ever created per session.
        """
        with self.lock:
            socks = list(self.clients.keys())
        if len(socks) == 2:
            a, b = socks   # a = first connected, b = second connected
            log("Two clients connected — swapping public keys (A=receiver, B=initiator)…", CYAN)
            # Client A: receives peer pubkey, waits passively for AES key
            self.send_to(a, {
                "type": "peer_pubkey",
                "pubkey": self.clients[b]["pubkey"],
                "peer": self.clients[b]["alias"],
                "role": "receiver"      # <-- do NOT generate AES key
            })
            # Client B: receives peer pubkey, must generate & send AES key
            self.send_to(b, {
                "type": "peer_pubkey",
                "pubkey": self.clients[a]["pubkey"],
                "peer": self.clients[a]["alias"],
                "role": "initiator"     # <-- generate & send AES key
            })

    def handle_client(self, conn, addr):
        alias = None
        buf = ""
        try:
            # ── Step 1: receive registration (alias + RSA public key) ──
            while "\n" not in buf:
                chunk = conn.recv(4096).decode()
                if not chunk:
                    return
                buf += chunk

            line, buf = buf.split("\n", 1)
            reg = json.loads(line)
            assert reg["type"] == "register"

            alias = reg["alias"]
            pubkey = reg["pubkey"]

            with self.lock:
                self.clients[conn] = {"alias": alias, "pubkey": pubkey}

            log(f"+ {alias} connected from {addr[0]}:{addr[1]}")
            self.send_to(conn, {"type": "welcome", "msg": f"Welcome, {alias}! Waiting for peer…"})

            # Notify existing clients
            self.broadcast({"type": "system", "msg": f"{alias} has joined the chat."}, exclude=conn)

            # If two clients are now present, swap public keys
            self.relay_pubkeys()

            # ── Step 2: relay loop ──────────────────────────────────────
            while True:
                while "\n" not in buf:
                    chunk = conn.recv(65536).decode()
                    if not chunk:
                        raise ConnectionResetError("Client disconnected")
                    buf += chunk

                line, buf = buf.split("\n", 1)
                packet = json.loads(line)
                ptype = packet.get("type")

                if ptype == "quit":
                    break
                elif ptype in ("aes_key_exchange", "message"):
                    # Pure relay — server never inspects encrypted payload
                    packet["from"] = alias
                    self.broadcast(packet, exclude=conn)
                    log(f"  relay [{ptype}] from {alias} → peers", DIM)

        except (ConnectionResetError, json.JSONDecodeError, AssertionError):
            pass
        except Exception as e:
            log(f"Error with {alias or addr}: {e}", RED)
        finally:
            with self.lock:
                self.clients.pop(conn, None)
            conn.close()
            if alias:
                log(f"- {alias} disconnected")
                self.broadcast({"type": "system", "msg": f"{alias} has left the chat."})

    def run(self):
        banner()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        log(f"Listening on {self.host}:{self.port}", GREEN)
        log("Waiting for clients…\n", DIM)

        def shutdown(sig, frame):
            log("\nShutting down server…", YELLOW)
            self.server_socket.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown)

        while True:
            try:
                conn, addr = self.server_socket.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()
            except OSError:
                break


if __name__ == "__main__":
    ChatServer(HOST, PORT).run()
