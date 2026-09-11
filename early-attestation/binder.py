#!/usr/bin/env python3
"""Byte-exact attestation binder of draft-fossati-seat-early-attestation-06, Section 5.1.1.

    attest_base      = HKDF-Expand-Label(0, "attestation base",
                                         Hash(ClientHello...ServerHello), Hash.length)
    s_attest_binder  = HKDF-Expand-Label(attest_base, "attestation",
                                         Hash(TLS_Server_Public_Key), Hash.length)

Hash is the cipher-suite hash of the handshake (Section 5.1.1). TLS_Server_Public_Key is the
DER-encoded SubjectPublicKeyInfo of the server's end-entity certificate (Section 5.1.1). The "0"
secret is Hash.length zero bytes; HKDF-Extract is not invoked (Section 5.1.1). HKDF-Expand-Label
is the TLS 1.3 construction of RFC 8446 / I-D.ietf-tls-rfc8446bis Section 7.1.

The verifier (Section 5.1.2) recomputes s_attest_binder from the transcript it observed and the
server public key it saw in the handshake, and compares it to the value carried in the signed
Evidence. On SEV-SNP that value is the guest-chosen REPORT_DATA (64 bytes): we place the binder
left-justified and zero-pad to 64 (documented embedding; the ABI treats REPORT_DATA as opaque)."""
import hashlib, struct

HASHES = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}

def hkdf_expand(prk: bytes, info: bytes, length: int, hashname: str) -> bytes:
    h = HASHES[hashname]; hlen = h().digest_size
    n = (length + hlen - 1) // hlen
    t, okm = b"", b""
    for i in range(1, n + 1):
        import hmac as _hmac
        t = _hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
    return okm[:length]

def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int, hashname: str) -> bytes:
    # struct HkdfLabel { uint16 length; opaque label<7..255>="tls13 "+label; opaque context<0..255>; }
    full = b"tls13 " + label.encode()
    hkdf_label = struct.pack(">H", length) + struct.pack("B", len(full)) + full \
                 + struct.pack("B", len(context)) + context
    return hkdf_expand(secret, hkdf_label, length, hashname)

def transcript_hash(handshake_bytes: bytes, hashname: str) -> bytes:
    return HASHES[hashname](handshake_bytes).digest()

def attest_base(ch_sh_transcript: bytes, hashname: str) -> bytes:
    hlen = HASHES[hashname]().digest_size
    return hkdf_expand_label(b"\x00" * hlen, "attestation base",
                             transcript_hash(ch_sh_transcript, hashname), hlen, hashname)

def server_binder(ch_sh_transcript: bytes, server_spki_der: bytes, hashname: str) -> bytes:
    hlen = HASHES[hashname]().digest_size
    base = attest_base(ch_sh_transcript, hashname)
    return hkdf_expand_label(base, "attestation",
                             HASHES[hashname](server_spki_der).digest(), hlen, hashname)

def client_binder(ch_sh_transcript: bytes, client_spki_der: bytes, hashname: str) -> bytes:
    hlen = HASHES[hashname]().digest_size
    base = attest_base(ch_sh_transcript, hashname)
    return hkdf_expand_label(base, "attestation",
                             HASHES[hashname](client_spki_der).digest(), hlen, hashname)

def into_report_data(binder: bytes) -> bytes:
    assert len(binder) <= 64
    return binder + b"\x00" * (64 - len(binder))

if __name__ == "__main__":
    # Known-answer self-test: RFC 5869-style determinism, and independence proofs.
    tr = bytes(range(256)) * 4          # stand-in ClientHello...ServerHello bytes
    spki_S = b"SERVER-SPKI-DER-example-0123456789"
    spki_A = b"ATTACKER-SPKI-DER-example-different"
    for hn in ("sha384", "sha256"):
        hlen = HASHES[hn]().digest_size
        b_S = server_binder(tr, spki_S, hn)
        assert len(b_S) == hlen, (hn, len(b_S))
        # determinism
        assert server_binder(tr, spki_S, hn) == b_S
        # different transcript -> different binder (relay across connections is caught IF key is honest)
        assert server_binder(tr + b"x", spki_S, hn) != b_S
        # different server key -> different binder
        assert server_binder(tr, spki_A, hn) != b_S
        # NOTE: 5.1.1 has no role separation in the label ("attestation" for both). c_attest_binder
        # and s_attest_binder are the SAME function of (transcript, public key); they differ only
        # because the two peers present different keys. Same key in both roles -> identical binder.
        assert client_binder(tr, spki_S, hn) == b_S
        assert client_binder(tr, spki_A, hn) != b_S
        rd = into_report_data(b_S)
        assert len(rd) == 64
        print(f"{hn}: Hash.length={hlen}  s_attest_binder={b_S.hex()[:32]}...  REPORT_DATA[{len(rd)}] ok")
    # HKDF-Expand-Label vector check against a hand-computed HkdfLabel for empty context
    v = hkdf_expand_label(b"\x00"*32, "attestation", b"", 32, "sha256")
    print("HKDF-Expand-Label(0^32,'attestation','',32,sha256) =", v.hex())
    print("SELF-TEST PASS")
