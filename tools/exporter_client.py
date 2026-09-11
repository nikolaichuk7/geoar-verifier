#!/usr/bin/env python3
"""Client and relay for the session-binding measurement (PROTOCOLS.md, protocol 5).

  exporter_client.py client <host> <port> "<public sentence>" <out.json>
      Connects with TLS 1.3, sends the nonce (SHA-512 of the sentence), receives the guest's blob, derives its OWN
      RFC 9266 exporter value from its side of the session and checks both binders:
        key binder:      report_key.REPORT_DATA == SHA-512(nonce || SPKI), signature over the nonce under that SPKI,
                         and the TLS peer's certificate key == that SPKI            (our earlier demo)
        exporter binder: report_exporter.REPORT_DATA == SHA-512(nonce || exporter_client)
      Both reports are also verified against the VCEK that AMD KDS issues for their CHIP_ID and TCB.
  exporter_client.py relay <listen_port> <host> <port> <cert.pem> <key.pem>
      A relay that holds the guest's TLS key (the leaked-key attacker of the binder analysis): terminates the client's
      TLS with that key, opens its own TLS session to the guest, forwards the nonce and the blob unchanged. Serves one
      client and exits. The client is then run against localhost:<listen_port>."""
import sys, os, json, socket, struct, hashlib, base64
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aws-vlek"))
from dual_verify import parse, sig_ok, chain_ok, load_cert, get
LABEL = b"EXPORTER-Channel-Binding"

def recv_exact(conn, n):
    b = b""
    while len(b) < n: b += conn.recv(n - len(b))
    return b
def tls_client(host, port):
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION); ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
    s = socket.create_connection((host, port), timeout=30); s.settimeout(None); conn = SSL.Connection(ctx, s); conn.set_connect_state(); conn.do_handshake(); return conn, s   # blocking socket: pyOpenSSL raises WantRead on timeout-mode sockets
def exchange(conn, N):
    conn.sendall(N.hex().encode() + b"\n"); n = struct.unpack(">I", recv_exact(conn, 4))[0]; return json.loads(recv_exact(conn, n))

def client(host, port, sentence, out):
    N = hashlib.sha512(sentence.encode()).digest(); conn, s = tls_client(host, port); blob = exchange(conn, N)
    exp_client = conn.export_keying_material(LABEL, 32, b""); peer = conn.get_peer_certificate()
    peer_spki = x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, peer)).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try: conn.shutdown()
    except Exception: pass
    s.close()
    spki = base64.b64decode(blob["spki"]); r_key = base64.b64decode(blob["report_key"]); r_exp = base64.b64decode(blob["report_exporter"]); sig = base64.b64decode(blob["sig_over_nonce"])
    res = {"peer": f"{host}:{port}", "tls": blob.get("tls_version"), "exporter_client": exp_client.hex(), "exporter_server_as_reported": blob["exporter_server"], "exporters_equal": exp_client.hex() == blob["exporter_server"]}
    try: serialization.load_der_public_key(spki).verify(sig, N, ec.ECDSA(hashes.SHA256())); sig_valid = True
    except Exception: sig_valid = False
    res["key_binder"] = {"report_data_is_sha512_nonce_spki": r_key[0x50:0x90] == hashlib.sha512(N + spki).digest(), "signature_over_nonce_valid": sig_valid, "tls_peer_key_equals_attested_spki": peer_spki == spki}
    res["key_binder"]["client_accepts"] = all(res["key_binder"].values())
    res["exporter_binder"] = {"report_data_is_sha512_nonce_exporter_client": r_exp[0x50:0x90] == hashlib.sha512(N + exp_client).digest()}
    res["exporter_binder"]["client_accepts"] = res["exporter_binder"]["report_data_is_sha512_nonce_exporter_client"]
    # the two reports themselves: VCEK from KDS by CHIP_ID and TCB
    try:
        chain = x509.load_pem_x509_certificates(get("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain")); f = parse(r_exp); bl, tee, snp, uc = f["tcb"]
        vcek = load_cert(get(f"https://kdsintf.amd.com/vcek/v1/Milan/{f['chip_id']}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}"))
        res["reports"] = {"chip_id_prefix": f["chip_id"][:16], "report_exporter_signature_ok": sig_ok(r_exp, vcek), "report_key_signature_ok": sig_ok(r_key, vcek), "vcek_chain_to_ark_ok": chain_ok(vcek, chain), "same_report_id": parse(r_exp)["report_id"] == parse(r_key)["report_id"]}
    except Exception as e: res["reports"] = {"error": repr(e)[:120]}
    d = os.path.dirname(out) or "."; os.makedirs(d, exist_ok=True); tag = os.path.basename(out)[:-5]
    open(os.path.join(d, tag + "-report-exporter.bin"), "wb").write(r_exp); open(os.path.join(d, tag + "-report-key.bin"), "wb").write(r_key); open(os.path.join(d, tag + "-blob.json"), "w").write(json.dumps(blob))
    json.dump(res, open(out, "w"), indent=1); print(json.dumps(res, indent=1))

def relay(listen_port, host, port, cert, key):
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, open(key, "rb").read())); ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, open(cert, "rb").read()))
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(("127.0.0.1", listen_port)); srv.listen(1); print(f"relay listening on 127.0.0.1:{listen_port}, holding the guest's key", flush=True)
    s, _ = srv.accept(); s.setblocking(True); c = SSL.Connection(ctx, s); c.set_accept_state(); c.do_handshake()
    line = b""
    while not line.endswith(b"\n"): line += c.recv(1)
    up, us = tls_client(host, port); up.sendall(line); n = struct.unpack(">I", recv_exact(up, 4))[0]; blob = recv_exact(up, n)
    exp_up = up.export_keying_material(LABEL, 32, b""); exp_down = c.export_keying_material(LABEL, 32, b"")
    c.sendall(struct.pack(">I", n) + blob); print(json.dumps({"relay": "forwarded", "exporter_relay_to_guest": exp_up.hex(), "exporter_client_to_relay": exp_down.hex()}), flush=True)
    for x in (up, c):
        try: x.shutdown()
        except Exception: pass
    us.close(); s.close(); srv.close()

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "client": client(a[1], int(a[2]), a[3], a[4])
    elif a[0] == "relay": relay(int(a[1]), a[2], int(a[3]), a[4], a[5])
    else: print(__doc__)
