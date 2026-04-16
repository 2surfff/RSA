"""
Secure chat client.

Key-exchange protocol:
  1. Send username to server (plaintext).
  2. Generate own RSA key pair.
  3. Receive server's RSA public key.
  4. Send own RSA public key to server.
  5. Receive symmetric key (RSA-encrypted by server with our public key).
  6. RSA-decrypt the symmetric key with our private key.

All subsequent messages are sent/received as (SHA-256 hash, XOR-encrypted text).
"""

import socket
import threading
import json

import rsa_impl
import crypto_utils


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip     = server_ip
        self.port          = port
        self.username      = username
        self.symmetric_key = None         # set after key exchange

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server:", e)
            return

        self.s.send(self.username.encode())

        print("[client]: Generating RSA key pair …")

        self.pub_key, self.priv_key = rsa_impl.generate_keypair(bits=512)

        server_pub = json.loads(crypto_utils.recv_data(self.s).decode())

        crypto_utils.send_data(self.s, json.dumps(self.pub_key).encode())

        enc_key_int = json.loads(crypto_utils.recv_data(self.s).decode())['key']

        key_int            = rsa_impl.decrypt(enc_key_int, self.priv_key)
        self.symmetric_key = key_int.to_bytes(32, 'big')

        print("[client]: Secure connection established! Start chatting.\n")

        message_handler = threading.Thread(target=self.read_handler, daemon=True)
        message_handler.start()

        input_handler = threading.Thread(target=self.write_handler, daemon=True)
        input_handler.start()

        message_handler.join()

    def read_handler(self):
        while True:
            try:
                raw = crypto_utils.recv_data(self.s)

                # Decrypt and verify integrity
                plaintext, integrity_ok = crypto_utils.unpack_secure(
                    raw, self.symmetric_key
                )

                message = plaintext.decode()

                if integrity_ok:
                    print(message)
                else:
                    print(f"[WARNING] Integrity check FAILED! Possibly tampered: {message}")

            except ConnectionError:
                print("[client]: Disconnected from server.")
                break
            except Exception as e:
                print(f"[client]: Read error: {e}")
                break


    def write_handler(self):
        while True:
            try:
                message   = input()
                plaintext = message.encode()
                payload = crypto_utils.pack_secure(plaintext, self.symmetric_key)
                crypto_utils.send_data(self.s, payload)

            except (ConnectionError, OSError):
                print("[client]: Connection lost.")
                break
            except Exception as e:
                print(f"[client]: Send error: {e}")
                break


if __name__ == "__main__":
    import sys
    username = sys.argv[1] if len(sys.argv) > 1 else input("Enter username: ")
    cl = Client("127.0.0.1", 9001, username)
    cl.init_connection()
