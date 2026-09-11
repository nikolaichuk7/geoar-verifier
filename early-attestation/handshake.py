#!/usr/bin/env python3
"""Run a real TLS 1.3 handshake in memory (OpenSSL via ssl.MemoryBIO), capture the exact
ClientHello...ServerHello transcript, and derive the Section 5.1.1 attestation binder from it.

Transcript-Hash(ClientHello...ServerHello) is the hash of the concatenated handshake-layer
messages (each [type||uint24 length||body]), per RFC 8446. We extract the ClientHello from the
client's first flight and the ServerHello from the server's first flight by parsing the TLS record
layer (skipping the 5-byte record headers and any ChangeCipherSpec), and stop at ServerHello.
Hash is the negotiated cipher suite's hash (SHA-384 for AES_256_GCM_SHA384 / CHACHA20_POLY1305,
SHA-256 for AES_128_GCM_SHA256), per Section 5.1.1."""
import ssl, socket, tempfile, os, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import binder as B

SUITE_HASH = {  # TLS 1.3 suite -> our binder hash name
    "TLS_AES_256_GCM_SHA384": "sha384", "TLS_CHACHA20_POLY1305_SHA256": "sha256",
    "TLS_AES_128_GCM_SHA256": "sha256",
}

def self_signed(tik: ec.EllipticCurvePrivateKey):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"attester.local")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tik.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(tik, hashes.SHA384()))
    return cert

def spki_der(tik):
    return tik.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)

def extract_first_handshake_msg(flight: bytes, want_hs_type: int):
    """Return the handshake-layer bytes of the first message of want_hs_type in a record flight."""
    i = 0; buf = b""
    while i + 5 <= len(flight):
        ctype = flight[i]; rlen = int.from_bytes(flight[i+3:i+5], "big"); frag = flight[i+5:i+5+rlen]
        if ctype == 22:  # handshake
            buf += frag
        i += 5 + rlen
    # buf is concatenated handshake messages; take the first one
    if len(buf) < 4: return None
    hs_type = buf[0]; hlen = int.from_bytes(buf[1:4], "big")
    if hs_type != want_hs_type: return None
    return buf[:4 + hlen]

def do_handshake_capture(tik: ec.EllipticCurvePrivateKey):
    """Drive a full TLS 1.3 handshake between an in-memory client and server; return
    (transcript_ch_sh, spki_der, hashname). The server uses `tik` as its certificate key."""
    cert = self_signed(tik)
    with tempfile.TemporaryDirectory() as d:
        cpath = os.path.join(d, "c.pem"); kpath = os.path.join(d, "k.pem")
        open(cpath, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        open(kpath, "wb").write(tik.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.minimum_version = ssl.TLSVersion.TLSv1_3
        sctx.maximum_version = ssl.TLSVersion.TLSv1_3; sctx.load_cert_chain(cpath, kpath)
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cctx.minimum_version = ssl.TLSVersion.TLSv1_3
        cctx.maximum_version = ssl.TLSVersion.TLSv1_3; cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        cin, cout = ssl.MemoryBIO(), ssl.MemoryBIO()
        sin, sout = ssl.MemoryBIO(), ssl.MemoryBIO()
        cobj = cctx.wrap_bio(cin, cout, server_hostname="attester.local")
        sobj = sctx.wrap_bio(sin, sout, server_side=True)
        client_flight = b""; server_flight = b""
        for _ in range(20):
            try: cobj.do_handshake()
            except ssl.SSLWantReadError: pass
            data = cout.read();  client_flight += data; sin.write(data)
            try: sobj.do_handshake()
            except ssl.SSLWantReadError: pass
            data = sout.read();  server_flight += data; cin.write(data)
            if cobj.cipher() and sobj.cipher(): break
        suite = sobj.cipher()[0]
        hn = SUITE_HASH.get(suite, "sha384")
        ch = extract_first_handshake_msg(client_flight, 1)   # ClientHello
        sh = extract_first_handshake_msg(server_flight, 2)   # ServerHello
        assert ch and sh, (ch is not None, sh is not None, suite)
        transcript = ch + sh
        return transcript, spki_der(tik), hn, suite

if __name__ == "__main__":
    tik = ec.generate_private_key(ec.SECP384R1())
    tr, spki, hn, suite = do_handshake_capture(tik)
    b_srv = B.server_binder(tr, spki, hn)
    # A second, independent handshake with the SAME key gives a DIFFERENT transcript (fresh randoms)
    tr2, spki2, hn2, _ = do_handshake_capture(tik)
    assert spki == spki2 and hn == hn2
    b_srv2 = B.server_binder(tr2, spki2, hn2)
    print("suite:", suite, " hash:", hn)
    print("transcript CH..SH length:", len(tr), "bytes;  ClientHello type", tr[0], " ServerHello present")
    print("s_attest_binder (run1):", b_srv.hex()[:32], "...")
    print("s_attest_binder (run2):", b_srv2.hex()[:32], "...")
    assert b_srv != b_srv2, "different sessions must give different binders (fresh randoms)"
    print("REPORT_DATA:", B.into_report_data(b_srv).hex()[:40], "... (64 bytes)")
    print("CAPTURE SELF-TEST PASS: real TLS1.3 handshake, transcript extracted, binder derived")
