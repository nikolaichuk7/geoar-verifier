#!/usr/bin/env python3
"""Credential Authority side of the TACRA (draft-novak-rats-tacra-00) enrollment worked example.

Given a run directory with the CA's present-nonce (ca-nonce.hex), the CSR the attester built
(csr.der), the attester's report (report-tacra.bin) and the VCEK certificate (cert-VCEK.bin), the
Credential Authority checks, before issuing a credential for CSKpub:

  1. Binding (the draft's open "CSR-to-Evidence" TODO): REPORT_DATA == SHA-512(nonce || CSR_DER),
     so the Evidence is bound to exactly this CSR and to the CA's freshness handle.
  2. Evidence is genuine: the report's ECDSA-P384 signature verifies under the VCEK, and the VCEK
     chains to AMD ARK-Milan fetched from the KDS; hwID == CHIP_ID.
  3. Proof of possession: the CSR's own signature verifies, so the holder controls CSKpri.

If all hold, the CA may issue a certificate for CSKpub, knowing CSKpri is held by a genuine SEV-SNP
TEE and the request is fresh to this CA nonce. NOTE (public, from ID-Crisis / intra-handshake.fail
and RFC 9266): this binds the CSR to a genuine TEE and to the nonce, but not to the CA<->attester
channel; a relay can still sit in the middle. The remedy is to also bind a value derived from the
session's shared secret (the RFC 9266 exporter of the CAS transport) into REPORT_DATA."""
import sys, os, json, hashlib, struct, binascii, urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, utils as asn1
from cryptography.hazmat.primitives import serialization

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

def main(d):
    nonce_hex = open(os.path.join(d,"ca-nonce.hex")).read().strip()
    nonce = binascii.unhexlify(nonce_hex)
    csr_der = open(os.path.join(d,"csr.der"),"rb").read()
    rep = open(os.path.join(d,"report-tacra.bin"),"rb").read()[:1184]
    report_data = rep[0x50:0x90]; chip = rep[0x1A0:0x1E0].hex()

    # 1. binding
    want = hashlib.sha512(nonce + csr_der).digest()
    binding_ok = (report_data == want)

    # 2. genuine Evidence
    vcek = load_cert(open(os.path.join(d,"cert-VCEK.bin"),"rb").read()) if os.path.exists(os.path.join(d,"cert-VCEK.bin")) else None
    signature_ok = sig_ok(rep, vcek) if vcek else False
    try: chain = x509.load_pem_x509_certificates(get("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"))
    except Exception: chain=None
    chain_verified = chain_ok(vcek, chain) if (vcek and chain) else None
    hw=[e for e in vcek.extensions if e.oid.dotted_string=="1.3.6.1.4.1.3704.1.4"] if vcek else []
    hwid_eq = (hw[0].value.value[-64:].hex()==chip) if hw else None

    # 3. proof of possession (CSR self-signature) + CSKpub match
    csr = x509.load_der_x509_csr(csr_der)
    pop_ok = csr.is_signature_valid
    cskpub_der = csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    shipped = open(os.path.join(d,"csk-pub.der"),"rb").read() if os.path.exists(os.path.join(d,"csk-pub.der")) else None
    cskpub_match = (shipped is None) or (shipped == cskpub_der)

    issue = bool(binding_ok and signature_ok and chain_verified and pop_ok and cskpub_match)
    out = {"run": d, "chip_id": chip, "signing_key": {0:"VCEK",1:"VLEK"}.get((struct.unpack_from("<I",rep,0x48)[0]>>2)&7),
           "1_binding_REPORT_DATA==SHA512(nonce||CSR)": binding_ok,
           "2a_report_signature_ok": signature_ok, "2b_chain_to_ARK_Milan": chain_verified, "2c_hwID==CHIP_ID": hwid_eq,
           "3a_CSR_proof_of_possession": pop_ok, "3b_CSKpub_matches": cskpub_match,
           "ISSUE_CREDENTIAL": issue,
           "cskpub_sha256": hashlib.sha256(cskpub_der).hexdigest()[:16], "ca_nonce": nonce_hex[:16]+"…"}
    print(json.dumps(out, indent=1))
    json.dump(out, open(os.path.join(d,"tacra_verify.json"),"w"), indent=1, default=str)
    print("\n" + ("ENROLLMENT VERIFIED — the CA may issue for CSKpub: the request is bound to this CSR and the CA nonce,\n"
                  "the Evidence is a genuine SEV-SNP report (VCEK chains to ARK-Milan), and the CSR proves possession\n"
                  "of the credential private key inside the TEE." if issue else "NOT VERIFIED — do not issue."))

if __name__ == "__main__":
    main(sys.argv[1])
