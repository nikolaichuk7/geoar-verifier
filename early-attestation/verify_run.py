#!/usr/bin/env python3
"""Offline client-side verification of a two-guest early-attestation run (Section 5.1.2).

Each guest directory holds: cap-transcript.bin (the ClientHello...ServerHello bytes the client saw),
spki.der (the server TLS identity key), report-binder.bin (the SEV-SNP report), cert-VCEK.bin
(the per-chip certificate the hypervisor handed the guest), hs.json (suite/hash). For each guest we
act as the Section 5.1.2 client: recompute s_attest_binder from the transcript and the SPKI, check
REPORT_DATA == binder, verify the report's signature with the VCEK, and verify the VCEK chain to the
AMD KDS ARK-Milan. We then print CHIP_ID and region. The attack succeeds when the attacker guest's
Evidence is ACCEPTED (binder + signature + chain) while its CHIP_ID/region differ from the server's,
the two guests sharing one TIK (identical SPKI): the client cannot tell it is not talking to S."""
import sys, os, json, hashlib, struct, urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils as asn1
import binder as B

UA = {"User-Agent": "geoar-verifier/1.0 (+https://github.com/nikolaichuk7/geoar-verifier)"}
def get(u): return urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=40).read()
def load_cert(b): return x509.load_pem_x509_certificate(b) if b[:10]==b"-----BEGIN" else x509.load_der_x509_certificate(b)

def sig_ok(rep, cert):
    r=int.from_bytes(rep[0x2A0:0x2A0+48],"little"); s=int.from_bytes(rep[0x2A0+72:0x2A0+120],"little")
    try: cert.public_key().verify(asn1.encode_dss_signature(r,s), rep[:0x2A0], ec.ECDSA(hashes.SHA384())); return True
    except Exception: return False
def chain_ok(leaf, chain):
    try:
        for child,parent in ((leaf,chain[0]),(chain[0],chain[1]),(chain[1],chain[1])):
            pk=parent.public_key()
            if isinstance(pk, rsa.RSAPublicKey): pk.verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters, child.signature_hash_algorithm)
            else: pk.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        return True
    except Exception: return False

def one(d):
    tr=open(os.path.join(d,"cap-transcript.bin"),"rb").read()
    spki=open(os.path.join(d,"spki.der"),"rb").read()
    rep=open(os.path.join(d,"report-binder.bin"),"rb").read()[:1184]
    hn=json.load(open(os.path.join(d,"cap-hs.json")))["hash"] if os.path.exists(os.path.join(d,"cap-hs.json")) else "sha384"
    meta=dict(l.split("=",1) for l in open(os.path.join(d,"metadata.txt")).read().split("\n") if "=" in l)
    want=B.into_report_data(B.server_binder(tr, spki, hn))
    got=rep[0x50:0x90]
    binder_match=(got==want)
    vcek=None
    for name in ("cert-VCEK.bin",):
        p=os.path.join(d,name)
        if os.path.exists(p): vcek=load_cert(open(p,"rb").read())
    chip=rep[0x1A0:0x1E0].hex()
    tcb=struct.unpack_from("<Q",rep,0x180)[0]; bl,tee,snp,uc=(tcb&0xff,(tcb>>8)&0xff,(tcb>>48)&0xff,(tcb>>56)&0xff)
    if vcek is None:  # fetch from KDS by CHIP_ID
        try: vcek=load_cert(get(f"https://kdsintf.amd.com/vcek/v1/Milan/{chip}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}"))
        except Exception as e: pass
    signature_ok = sig_ok(rep, vcek) if vcek else False
    try: chain=x509.load_pem_x509_certificates(get("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"))
    except Exception: chain=None
    chain_verified = (chain_ok(vcek, chain) if (vcek and chain) else None)
    hw=[e for e in vcek.extensions if e.oid.dotted_string=="1.3.6.1.4.1.3704.1.4"] if vcek else []
    hwid_eq = (hw[0].value.value[-64:].hex()==chip) if hw else None
    return {"dir":d,"role":meta.get("role"),"region":meta.get("zone"),"instance":meta.get("instance"),
            "spki_sha256":hashlib.sha256(spki).hexdigest()[:16],"transcript_sha256":hashlib.sha256(tr).hexdigest()[:16],
            "signing_key":{0:"VCEK",1:"VLEK"}.get((struct.unpack_from("<I",rep,0x48)[0]>>2)&7),
            "chip_id":chip,"binder_match":binder_match,"report_signature_ok":signature_ok,
            "chain_to_ARK_Milan":chain_verified,"hwid_equals_chip_id":hwid_eq,
            "accept": bool(binder_match and signature_ok and chain_verified)}

def main(server_dir, attacker_dir):
    S=one(server_dir); A=one(attacker_dir)
    print(json.dumps({"server":S,"attacker":A}, indent=1))
    print("\n=== Section 5.1.2 client decision ===")
    for r in (S,A):
        print(f"{r['role']:8} region={r['region']:16} chip={r['chip_id'][:16]}..  "
              f"accept={r['accept']}  binder={r['binder_match']} sig={r['report_signature_ok']} chain={r['chain_to_ARK_Milan']}")
    same_key = S["spki_sha256"]==A["spki_sha256"]
    diff_chip = S["chip_id"]!=A["chip_id"]
    print(f"\nsame server TIK (SPKI) on both: {same_key};  different CHIP_ID: {diff_chip}")
    if A["accept"] and diff_chip and same_key:
        print("ATTACK CONFIRMED: the client accepts genuine, KDS-verified Evidence from the attacker's")
        print("chip (a different machine, "+A['region']+") while the server's key it saw is identical,")
        print("so it cannot tell it is not talking to the server ("+S['region']+"). Section 5.1.1 binder relayed.")
    json.dump({"server":S,"attacker":A,"same_key":same_key,"diff_chip":diff_chip}, open("verify_run.json","w"), indent=1, default=str)

if __name__=="__main__":
    main(sys.argv[1], sys.argv[2])
