import socket
import threading
import json
import base64
import hashlib
import hmac
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters

HOST = "127.0.0.1"
PORT = 9999

# Fail-mode flags (for demonstrating vulnerabilities)
args = __import__("sys").argv[1:]
SKIP_SEQ = "--skip-seq" in args
SKIP_HMAC = "--skip-hmac" in args
if SKIP_SEQ:
    print("sequence numbers NOT enforced")
if SKIP_HMAC:
    print("HMAC NOT verified")

# Generate Server RSA keypair
print("Loading RSA keypair")
with open("server_rsa_private.pem", "rb") as f:
    server_rsa_private = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
server_rsa_public = server_rsa_private.public_key()

server_rsa_public_pem = server_rsa_public.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Generate DH Parameters (shared by all)
print("Generating DH parameters")
dh_params = generate_parameters(generator=2, key_size=2048, backend=default_backend())
dh_params_pem = dh_params.parameter_bytes(
    serialization.Encoding.PEM,
    serialization.ParameterFormat.PKCS3
).decode()
print("DH parameters ready")

# Client state
clients = {} # addr -> { socket, aes_key, hmac_key, username, rsa_pub }
clients_lock = threading.Lock()


def sign_data(data: bytes) -> str:
    sig = server_rsa_private.sign(data, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())
    return base64.b64encode(sig).decode()


def broadcast(message_dict: dict, exclude_addr=None):
    with clients_lock:
        snapshot = list(clients.items())
    for addr, info in snapshot:
        if addr == exclude_addr:
            continue
        try:
            send_encrypted(info["socket"], message_dict, info["aes_key"], info["hmac_key"])
        except Exception as e:
            print(f"Broadcast error to {addr}: {e}")


def send_encrypted(sock, message_dict: dict, aes_key: bytes, hmac_key: bytes):
    plaintext = json.dumps(message_dict).encode()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    packet = json.dumps({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac).decode()
    }).encode()
    length = len(packet).to_bytes(4, "big")
    sock.sendall(length + packet)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf


def recv_encrypted(sock, aes_key: bytes, hmac_key: bytes) -> dict:
    length_bytes = recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    packet = json.loads(recv_exact(sock, length))
    nonce = base64.b64decode(packet["nonce"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    mac = base64.b64decode(packet["hmac"])
    if SKIP_HMAC:
        print("Skipping HMAC check")
    else:
        expected_mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification FAILED!")
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        if SKIP_HMAC:
            raise ValueError("AES-GCM auth tag FAILED")
        raise
    return json.loads(plaintext)


def handle_client(conn, addr):
    print(f"[SERVER] New connection from {addr}")
    try:
        # Send server RSA public key + DH params
        hello = json.dumps({
            "server_rsa_pub": server_rsa_public_pem,
            "dh_params": dh_params_pem
        }).encode()
        conn.sendall(len(hello).to_bytes(4, "big") + hello)

        # Receive client's RSA public key + DH public key 
        length = int.from_bytes(recv_exact(conn, 4), "big")
        client_hello = json.loads(recv_exact(conn, length))
        client_rsa_pub_pem = client_hello["client_rsa_pub"]
        client_dh_pub_pem = client_hello["client_dh_pub"]
        username = client_hello["username"]

        client_rsa_pub = serialization.load_pem_public_key(
            client_rsa_pub_pem.encode(), backend=default_backend()
        )

        # Server performs DH – generate server DH keypair 
        server_dh_private = dh_params.generate_private_key()
        server_dh_public = server_dh_private.public_key()
        server_dh_pub_pem = server_dh_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Load client DH public key
        client_dh_pub = serialization.load_pem_public_key(
            client_dh_pub_pem.encode(), backend=default_backend()
        )

        # Compute shared secret 
        shared_secret = server_dh_private.exchange(client_dh_pub)
        derived = HKDF(
            algorithm=hashes.SHA256(), length=64, salt=None,
            info=b"chat-keys", backend=default_backend()
        ).derive(shared_secret)
        aes_key = derived[:32]
        hmac_key = derived[32:]

        # Sign server DH public key and send 
        sig = sign_data(server_dh_pub_pem.encode())
        response = json.dumps({
            "server_dh_pub": server_dh_pub_pem,
            "signature": sig
        }).encode()
        conn.sendall(len(response).to_bytes(4, "big") + response)

        # Receive client's signed DH public key (verify) 
        length = int.from_bytes(recv_exact(conn, 4), "big")
        client_sig_msg = json.loads(recv_exact(conn, length))
        client_sig = base64.b64decode(client_sig_msg["signature"])
        try:
            client_rsa_pub.verify(client_sig, client_dh_pub_pem.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"RSA signature from {username}@{addr} VERIFIED")
        except Exception:
            print(f"RSA signature from {addr} INVALID")
            conn.close()
            return

        # Register client
        with clients_lock:
            clients[addr] = {
                "socket": conn,
                "aes_key": aes_key,
                "hmac_key": hmac_key,
                "username": username,
                "rsa_pub": client_rsa_pub,
                "seq_in": 0,
            }

        print(f"{username}@{addr} fully authenticated.")

        # Announce to all
        broadcast({"type": "system", "text": f"{username} joined the chat."}, exclude_addr=addr)
        send_encrypted(conn, {"type": "system", "text": "Connected. Start chatting!"}, aes_key, hmac_key)

        # Message loop
        expected_seq = 0
        while True:
            try:
                msg = recv_encrypted(conn, aes_key, hmac_key)
            except (ConnectionError, ConnectionResetError, EOFError):
                raise 
            except ValueError as e:
                print(f"Dropping bad packet from {username}: {e}")
                send_encrypted(conn, {"type": "error", "text": f"Packet rejected: {e}"}, aes_key, hmac_key)
                continue

            # Sequence number check (replay protection)
            seq = msg.get("seq", -1)
            if SKIP_SEQ:
                pass # --skip-seq: accept any sequence number, replay attacks succeed
            elif seq != expected_seq:
                print(f"Replay/out-of-order from {username}: expected {expected_seq}, got {seq}")
                send_encrypted(conn, {"type": "error", "text": f"Bad sequence number (got {seq}, expected {expected_seq}). Possible replay attack!"}, aes_key, hmac_key)
                continue
            expected_seq = seq + 1

            if msg.get("type") == "message":
                text = msg.get("text", "")
                print(f"[{username}] {text}")
                broadcast({
                    "type": "message",
                    "sender": username,
                    "text": text,
                    "seq": seq,
                    "ts": msg.get("ts", 0)
                }, exclude_addr=addr)

    except (ConnectionError, ConnectionResetError, EOFError):
        print(f"{addr} disconnected.")
    except Exception as e:
        print(f"Error with {addr}: {e}")
    finally:
        with clients_lock:
            info = clients.pop(addr, None)
        if info:
            broadcast({"type": "system", "text": f"{info['username']} left the chat."})
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    print(f"Listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
