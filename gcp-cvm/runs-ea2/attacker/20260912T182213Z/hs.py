#!/usr/bin/env python3
"""Guest-side, stdlib-only: run a real TLS 1.3 handshake (ssl.MemoryBIO), capture the exact
ClientHello...ServerHello transcript, derive the Section 5.1.1 server attestation binder, and
write REPORT_DATA. Cert/key/SPKI are produced by openssl in the caller (no `cryptography` dep).

argv: cert.pem key.pem spki.der out_prefix"""
import ssl, sys, json, hashlib, hmac, struct

SUITE_HASH = {"TLS_AES_256_GCM_SHA384": "sha384", "TLS_CHACHA20_POLY1305_SHA256": "sha256",
              "TLS_AES_128_GCM_SHA256": "sha256"}
HASHES = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}

def hkdf_expand(prk, info, length, hn):
    h = HASHES[hn]; hlen = h().digest_size; n = (length + hlen - 1)//hlen; t=b""; okm=b""
    for i in range(1, n+1):
        t = hmac.new(prk, t+info+bytes([i]), h).digest(); okm += t
    return okm[:length]

def hkdf_expand_label(secret, label, context, length, hn):
    full = b"tls13 " + label.encode()
    lbl = struct.pack(">H", length) + struct.pack("B", len(full)) + full + struct.pack("B", len(context)) + context
    return hkdf_expand(secret, lbl, length, hn)

def server_binder(transcript, spki_der, hn):
    hlen = HASHES[hn]().digest_size
    base = hkdf_expand_label(b"\x00"*hlen, "attestation base", HASHES[hn](transcript).digest(), hlen, hn)
    return hkdf_expand_label(base, "attestation", HASHES[hn](spki_der).digest(), hlen, hn)

def first_hs_msg(flight, want):
    i=0; buf=b""
    while i+5 <= len(flight):
        ctype=flight[i]; rlen=int.from_bytes(flight[i+3:i+5],"big"); buf += flight[i+5:i+5+rlen] if ctype==22 else b""; i+=5+rlen
    if len(buf)<4 or buf[0]!=want: return None
    return buf[:4+int.from_bytes(buf[1:4],"big")]

def capture(cert, key):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.minimum_version=sctx.maximum_version=ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(cert, key)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cctx.minimum_version=cctx.maximum_version=ssl.TLSVersion.TLSv1_3
    cctx.check_hostname=False; cctx.verify_mode=ssl.CERT_NONE
    cin,cout,sin,sout = ssl.MemoryBIO(),ssl.MemoryBIO(),ssl.MemoryBIO(),ssl.MemoryBIO()
    cobj=cctx.wrap_bio(cin,cout,server_hostname="attester.local"); sobj=sctx.wrap_bio(sin,sout,server_side=True)
    cflight=b""; sflight=b""
    for _ in range(20):
        try: cobj.do_handshake()
        except ssl.SSLWantReadError: pass
        d=cout.read(); cflight+=d; sin.write(d)
        try: sobj.do_handshake()
        except ssl.SSLWantReadError: pass
        d=sout.read(); sflight+=d; cin.write(d)
        if cobj.cipher() and sobj.cipher(): break
    suite=sobj.cipher()[0]; hn=SUITE_HASH.get(suite,"sha384")
    ch=first_hs_msg(cflight,1); sh=first_hs_msg(sflight,2)
    assert ch and sh, (ch is not None, sh is not None, suite)
    return ch+sh, hn, suite

if __name__=="__main__":
    cert,key,spki_path,pref = sys.argv[1:5]
    spki=open(spki_path,"rb").read()
    tr,hn,suite=capture(cert,key)
    binder=server_binder(tr,spki,hn); rd=binder+b"\x00"*(64-len(binder))
    open(pref+"-transcript.bin","wb").write(tr)
    open(pref+"-reportdata.bin","wb").write(rd)
    json.dump({"suite":suite,"hash":hn,"transcript_len":len(tr),"transcript_sha256":hashlib.sha256(tr).hexdigest(),
               "spki_sha256":hashlib.sha256(spki).hexdigest(),"binder":binder.hex(),"report_data":rd.hex()},
              open(pref+"-hs.json","w"))
    print("OK suite",suite,"hash",hn,"tr",len(tr),"binder",binder.hex()[:24])
