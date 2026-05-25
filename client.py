import socket
import threading
import json
import base64
import hashlib
import hmac as hmac_lib
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

HOST = "127.0.0.1"
PORT = 9999

# Parse CLI args
args = sys.argv[1:]
username = "Anonymous"
non_flag_args = [a for a in args if not a.startswith("--")]
if non_flag_args:
    username = non_flag_args[0]

# --port <number>
PORT = 9999
if "--port" in args:
    idx = args.index("--port")
    try:
        PORT = int(args[idx + 1])
    except (IndexError, ValueError):
        print("Usage: --port <number>")
        sys.exit(1)

FLAG_LEAK_KEY = "--leak-key" in args
FLAG_SKIP_SIG_VERIFY = "--skip-sig-verify" in args
FLAG_SKIP_HMAC = "--skip-hmac" in args
FLAG_SKIP_SEQ = "--skip-seq" in args

# Print active fail modes
print(f"Secure Chat Client — User: {username}")
if FLAG_LEAK_KEY:
    print(f"FAIL MODE: --leak-key: AES session key will be printed!")
if FLAG_SKIP_SIG_VERIFY:
    print(f"FAIL MODE: --skip-sig-verify: RSA signatures NOT verified")
if FLAG_SKIP_HMAC:
    print(f"FAIL MODE: --skip-hmac: HMAC NOT checked")
if FLAG_SKIP_SEQ:
    print(f"FAIL MODE: --skip-seq: Sequence numbers NOT checked")
if not any([FLAG_LEAK_KEY, FLAG_SKIP_SIG_VERIFY, FLAG_SKIP_HMAC, FLAG_SKIP_SEQ]):
    print(f"All defenses ENABLED.")

# Generate client RSA keypair
print(f"Generating RSA keypair")
client_rsa_private = generate_private_key(public_exponent=65537, key_size=2048)
client_rsa_public = client_rsa_private.public_key()
client_rsa_pub_pem = client_rsa_public.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Load pre-shared server RSA public key (acts like a certificate / trust anchor)
# This is what prevents MITM: we know the real server key before connecting.
try:
    with open("server_rsa_public.pem", "rb") as f:
        PINNED_SERVER_RSA_PUB = serialization.load_pem_public_key(f.read(), backend=default_backend())
    print(f"Loaded pinned server RSA public key from server_rsa_public.pem")
except FileNotFoundError:
    print(f"server_rsa_public.pem not found")
    PINNED_SERVER_RSA_PUB = None


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf


def send_encrypted(sock, message_dict: dict, aes_key: bytes, hmac_key: bytes):
    plaintext = json.dumps(message_dict).encode()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    mac = hmac_lib.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    packet = json.dumps({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac).decode()
    }).encode()
    length = len(packet).to_bytes(4, "big")
    sock.sendall(length + packet)


def recv_encrypted(sock, aes_key: bytes, hmac_key: bytes) -> dict:
    length_bytes = recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    packet = json.loads(recv_exact(sock, length))
    nonce = base64.b64decode(packet["nonce"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    mac = base64.b64decode(packet["hmac"])

    if FLAG_SKIP_HMAC:
        print(f"Skipping HMAC verification")
    else:
        expected_mac = hmac_lib.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac_lib.compare_digest(mac, expected_mac):
            raise ValueError("HMAC FAILED, message was tampered with")

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)


def listen_for_messages(sock, aes_key, hmac_key, stop_event):
    expected_seq = 0
    while not stop_event.is_set():
        try:
            msg = recv_encrypted(sock, aes_key, hmac_key)
            mtype = msg.get("type", "")

            if mtype == "message":
                seq = msg.get("seq", -1)
                sender = msg.get("sender", "?")
                text = msg.get("text", "")

                if FLAG_SKIP_SEQ:
                    print(f"Seq check skipped. Got seq={seq}")
                else:
                    if seq < expected_seq:
                        print(f"REPLAY ATTACK DETECTED from {sender}! seq={seq} already seen (expected >= {expected_seq}). Message DROPPED.")
                        continue
                    elif seq != expected_seq:
                        print(f"Out of order message from {sender}: expected {expected_seq}, got {seq}.")
                    expected_seq = seq + 1

                print(f"\n[{sender}] {text}")

            elif mtype == "system":
                print(f"\n[SYSTEM] {msg.get('text', '')}")
            elif mtype == "error":
                print(msg.get("text", "Unknown server error"))

            print(f"[{username}] ", end="", flush=True)

        except ValueError as e:
            print(str(e))
            stop_event.set()
            break
        except (ConnectionError, EOFError):
            print(f"Disconnected from server.")
            stop_event.set()
            break
        except Exception as e:
            print(f"Receive error: {e}")
            stop_event.set()
            break


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    # Receive server hello (RSA pub + DH params)
    length = int.from_bytes(recv_exact(sock, 4), "big")
    server_hello = json.loads(recv_exact(sock, length))
    server_rsa_pub_pem = server_hello["server_rsa_pub"]
    dh_params_pem = server_hello["dh_params"]

    # Use the pinned key for verification
    # If attacker substitutes their own RSA key in the server hello, we ignore it
    # and verify against the pre-shared key we already have on disk.
    server_rsa_pub_from_wire = serialization.load_pem_public_key(
        server_rsa_pub_pem.encode(), backend=default_backend()
    )
    if PINNED_SERVER_RSA_PUB is not None:
        server_rsa_pub = PINNED_SERVER_RSA_PUB
        # Check if the wire key matches what we expect
        wire_pem = server_rsa_pub_from_wire.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pinned_pem = PINNED_SERVER_RSA_PUB.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if wire_pem != pinned_pem:
            if FLAG_SKIP_SIG_VERIFY:
                server_rsa_pub = server_rsa_pub_from_wire
            else:
                print(f"MITM DETECTED: Server sent a different RSA key than the pinned one! Aborting.")
                sock.close()
                sys.exit(1)
        else:
            print(f"Server RSA key matches pinned key.")
    else:
        server_rsa_pub = server_rsa_pub_from_wire
        print(f"No pinned key")
    dh_params = serialization.load_pem_parameters(
        dh_params_pem.encode(), backend=default_backend()
    )

    # Generate client DH keypair 
    client_dh_private = dh_params.generate_private_key()
    client_dh_public = client_dh_private.public_key()
    client_dh_pub_pem = client_dh_public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Send client hello
    client_hello = json.dumps({
        "client_rsa_pub": client_rsa_pub_pem,
        "client_dh_pub": client_dh_pub_pem,
        "username": username
    }).encode()
    sock.sendall(len(client_hello).to_bytes(4, "big") + client_hello)

    # Receive server DH public key + RSA signature
    length = int.from_bytes(recv_exact(sock, 4), "big")
    server_response = json.loads(recv_exact(sock, length))
    server_dh_pub_pem = server_response["server_dh_pub"]
    server_sig = base64.b64decode(server_response["signature"])

    # Verify server's RSA signature over its DH public key
    if FLAG_SKIP_SIG_VERIFY:
        print(f"Skipping RSA signature verification")
    else:
        try:
            server_rsa_pub.verify(
                server_sig,
                server_dh_pub_pem.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"Server RSA signature verified.")
        except Exception:
            print(f"Server RSA signature INVALID")
            sock.close()
            sys.exit(1)

    server_dh_pub = serialization.load_pem_public_key(
        server_dh_pub_pem.encode(), backend=default_backend()
    )

    # Compute shared secret 
    shared_secret = client_dh_private.exchange(server_dh_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None,
        info=b"chat-keys", backend=default_backend()
    ).derive(shared_secret)
    aes_key = derived[:32]
    hmac_key = derived[32:]

    if FLAG_LEAK_KEY:
        print(f"AES session key: {aes_key.hex()}")
        print(f"HMAC key: {hmac_key.hex()}")
    else:
        print(f"Session keys derived. AES key fingerprint: {aes_key[:4].hex()}")

    # Send client's signed DH public key
    client_sig = client_rsa_private.sign(
        client_dh_pub_pem.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sig_msg = json.dumps({"signature": base64.b64encode(client_sig).decode()}).encode()
    sock.sendall(len(sig_msg).to_bytes(4, "big") + sig_msg)

    print(f"Handshake complete")
    print()

    stop_event = threading.Event()
    t = threading.Thread(target=listen_for_messages, args=(sock, aes_key, hmac_key, stop_event), daemon=True)
    t.start()

    seq = 0
    try:
        while not stop_event.is_set():
            print(f"[{username}] ", end="", flush=True)
            text = input()
            if text.strip().lower() in ("/quit", "/exit"):
                break
            send_encrypted(sock, {
                "type": "message",
                "text": text,
                "seq": seq,
                "ts": time.time()
            }, aes_key, hmac_key)
            seq += 1
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop_event.set()
        sock.close()
        print(f"Client exited.")


if __name__ == "__main__":
    main()
