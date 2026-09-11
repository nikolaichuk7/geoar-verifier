import socket, json, hashlib, base64, struct, os, fcntl, ctypes, time, sys
from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
LABEL = b"EXPORTER-Channel-Binding"
class Req(ctypes.Structure):   _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]
class Resp(ctypes.Structure):  _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure): _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
def snp_report(user_data):
    req = Req(); ctypes.memmove(req.user_data, user_data, 64); req.vmpl = 0; req.flags = 0; resp = Resp(); io = Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0)
    fd = os.open("/dev/sev-guest", os.O_RDWR); fcntl.ioctl(fd, 0xC0205300, io); os.close(fd)
    if resp.status != 0 or resp.report_size != 1184: raise RuntimeError(f"fw_status {resp.status}")
    return bytes(resp.report[:1184])
key_pem = open("guest-tls.key", "rb").read(); cert_pem = open("guest-tls.crt", "rb").read()
priv = serialization.load_pem_private_key(key_pem, None); spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)); ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(("0.0.0.0", 8443)); srv.listen(5); srv.settimeout(10)
deadline = time.time() + 15 * 60; sessions = []; n = 0
print("serving on 8443 until", time.strftime("%H:%M:%SZ", time.gmtime(deadline)), flush=True)
while time.time() < deadline:
    try: s, addr = srv.accept()
    except socket.timeout: continue
    n += 1; rec = {"n": n, "peer": addr[0], "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}; s.setblocking(True); conn = SSL.Connection(ctx, s); conn.set_accept_state()   # blocking: pyOpenSSL raises WantRead on timeout-mode sockets
    try:
        conn.do_handshake(); line = b""
        while not line.endswith(b"\n") and len(line) < 200: line += conn.recv(1)
        N = bytes.fromhex(line.strip().decode()); exp = conn.export_keying_material(LABEL, 32, b"")
        r_exp = snp_report(hashlib.sha512(N + exp).digest()); r_key = snp_report(hashlib.sha512(N + spki).digest()); sig = priv.sign(N, ec.ECDSA(hashes.SHA256()))
        blob = json.dumps({"tls_version": conn.get_protocol_version_name(), "exporter_server": exp.hex(), "report_exporter": base64.b64encode(r_exp).decode(), "report_key": base64.b64encode(r_key).decode(),
                           "spki": base64.b64encode(spki).decode(), "sig_over_nonce": base64.b64encode(sig).decode(), "cert": base64.b64encode(cert_pem).decode()}).encode()
        conn.sendall(struct.pack(">I", len(blob)) + blob)
        open(f"session-{n:02d}-report-exporter.bin", "wb").write(r_exp); open(f"session-{n:02d}-report-key.bin", "wb").write(r_key)
        rec.update({"nonce_hex": N.hex()[:16] + "...", "exporter_server": exp.hex(), "tls": conn.get_protocol_version_name(), "ok": True})
    except Exception as e: rec.update({"ok": False, "error": repr(e)[:160]})
    finally:
        try: conn.shutdown()
        except Exception: pass
        s.close()
    sessions.append(rec); print(json.dumps(rec), flush=True); json.dump(sessions, open("exporter-sessions.json", "w"), indent=1)
json.dump(sessions, open("exporter-sessions.json", "w"), indent=1)
