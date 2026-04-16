"""
Secure chat server.

Key-exchange protocol (per client):
  1. Receive username (plaintext).
  2. Send server's RSA public key to client.
  3. Receive client's RSA public key.
  4. Generate a unique 32-byte symmetric key for this client.
  5. RSA-encrypt the symmetric key with the client's public key and send it.

After setup every message is exchanged as (SHA-256 hash, XOR-encrypted text).
"""

import socket
import threading
import json

import rsa_impl
import crypto_utils


class Server:
    def __init__(self, port: int) -> None:
        self.host   = '127.0.0.1'
        self.port   = port
        self.clients         = []
        self.username_lookup = {}
        self.symmetric_keys  = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        print("[server]: Generating RSA key pair …")
        self.pub_key, self.priv_key = rsa_impl.generate_keypair(bits=512)
        print(f"[server]: Listening on {self.host}:{self.port}")

        while True:
            c, addr = self.s.accept()
            threading.Thread(
                target=self._setup_client, args=(c, addr), daemon=True
            ).start()

    def _setup_client(self, c: socket.socket, addr):
        """
        Perform RSA key exchange with a newly connected client,
        then hand off to the message-handling loop.
        """
        try:
            username = c.recv(1024).decode()
            print(f"[server]: {username} tries to connect")

            crypto_utils.send_data(c, json.dumps(self.pub_key).encode())
            client_pub = json.loads(crypto_utils.recv_data(c).decode())
            sym_key = crypto_utils.generate_symmetric_key(32)

            key_int     = int.from_bytes(sym_key, 'big')
            enc_key_int = rsa_impl.encrypt(key_int, client_pub)
            crypto_utils.send_data(c, json.dumps({'key': enc_key_int}).encode())
            self.symmetric_keys[c]  = sym_key
            self.username_lookup[c] = username
            self.clients.append(c)

            self.broadcast(f"new person has joined: {username}", exclude=c)
            print(f"[server]: {username} connected — key exchange complete.")

            self._handle_client(c)

        except Exception as e:
            print(f"[server]: Setup error: {e}")
            c.close()

    def _handle_client(self, c: socket.socket):
        username = self.username_lookup.get(c, "unknown")

        while True:
            try:
                raw = crypto_utils.recv_data(c)
                key = self.symmetric_keys[c]

                plaintext, integrity_ok = crypto_utils.unpack_secure(raw, key)

                if not integrity_ok:
                    print(f"[server]: ⚠ Integrity check FAILED for message from {username}!")
                    continue

                message = plaintext.decode()
                print(f"[server]: {username}: {message}  ✓ integrity OK")
                self.broadcast(f"{username}: {message}", exclude=c)

            except (ConnectionError, OSError):
                print(f"[server]: {username} disconnected.")
                self._remove_client(c)
                break
            except Exception as e:
                print(f"[server]: Error from {username}: {e}")
                self._remove_client(c)
                break

    def broadcast(self, msg: str, exclude=None):
        """
        Send an encrypted message to every connected client.
        Each client gets the message XOR-encrypted with *their* unique symmetric key.
        """
        msg_bytes = msg.encode()

        for client in list(self.clients):
            if client == exclude:
                continue
            try:
                key     = self.symmetric_keys[client]
                payload = crypto_utils.pack_secure(msg_bytes, key)
                crypto_utils.send_data(client, payload)
            except Exception as e:
                name = self.username_lookup.get(client, "?")
                print(f"[server]: Could not send to {name}: {e}")

    def _remove_client(self, c: socket.socket):
        username = self.username_lookup.pop(c, "unknown")
        self.symmetric_keys.pop(c, None)
        if c in self.clients:
            self.clients.remove(c)
        self.broadcast(f"{username} has left the chat.")
        try:
            c.close()
        except Exception:
            pass


if __name__ == "__main__":
    s = Server(9001)
    s.start()
