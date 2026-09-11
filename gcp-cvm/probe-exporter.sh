#!/bin/bash
# Session-binding probe (protocol 5, corrected after Sardar's binder point of 11 Sept). The guest runs a TLS 1.3
# server for fifteen minutes. For every client connection it takes the client's nonce, derives the RFC 9266
# exporter value of that very session (label "EXPORTER-Channel-Binding", empty context, 32 bytes) and requests two
# SEV-SNP reports: REPORT_DATA = SHA-512(nonce || exporter)   [binder: session shared secret]
#                  REPORT_DATA = SHA-512(nonce || SPKI)       [binder: the server's TLS public key, our earlier demo]
# plus a signature over the nonce with the TLS key. The TLS key pair was generated on the operator's machine so that
# a relay run there can model an attacker who holds the server's key. Everything is logged and archived as usual.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=google; IID=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name); ZONE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "captured=$STAMP"; echo "probe=exporter"; } > metadata.txt
export DEBIAN_FRONTEND=noninteractive; apt-get update -qq > apt.log 2>&1; apt-get install -y -qq python3-openssl python3-cryptography > /dev/null 2>> apt.log
echo "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrVENDQVRlZ0F3SUJBZ0lVVW1UeVR0RmM1bStyUUIwYklHU2RsZVpFK1Jjd0NnWUlLb1pJemowRUF3SXcKSGpFY01Cb0dBMVVFQXd3VGNtRjBjeTFsZUhCdmNuUmxjaTFuZFdWemREQWVGdzB5TmpBNU1URXhOelV4TlRKYQpGdzB5TmpBNU1UUXhOelV4TlRKYU1CNHhIREFhQmdOVkJBTU1FM0poZEhNdFpYaHdiM0owWlhJdFozVmxjM1F3CldUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRYS9ETHArMWMrMEhNOUZxOEpNU0J6amg5ZGszWlAKRDRVTVphZXBnNGNOUlBKWXlYTVl4ci9rYno2WFE3eXllSXpJdmNOZkxRM3hWdTB4MHNCT2tpMWRvMU13VVRBZApCZ05WSFE0RUZnUVV2VkdpT2dwc05oNFIrckovVGlGZ0Y0d3MvdTh3SHdZRFZSMGpCQmd3Rm9BVXZWR2lPZ3BzCk5oNFIrckovVGlGZ0Y0d3MvdTh3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFLQmdncWhrak9QUVFEQWdOSUFEQkYKQWlFQTY0bytnSVFlYm03dFdHZ0ZVVHVEaVFwaXU0UlNhbDcvMjBZOGJiUzZEeUVDSURRV2puSmdLTXJKMk1aNQpaUC9DckxrcTBRcnI5allpTk9RL1Fta1Z1OWxnCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K" | base64 -d > guest-tls.crt; echo "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3FqcVMvRWFrbEtrazZFa0kKM2RQOXJ3WGJITTFyaW53VU0ycXY0c2dvY3V5aFJBTkNBQVFhL0RMcCsxYyswSE05RnE4Sk1TQnpqaDlkazNaUApENFVNWmFlcGc0Y05SUEpZeVhNWXhyL2tiejZYUTd5eWVJekl2Y05mTFEzeFZ1MHgwc0JPa2kxZAotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==" | base64 -d > guest-tls.key
cat > server.py <<'PY'
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
PY
python3 server.py > server.log 2>&1
sha256sum session-*.bin guest-tls.crt exporter-sessions.json > sha256sums.txt 2>/dev/null; rm -f guest-tls.key
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true; sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
