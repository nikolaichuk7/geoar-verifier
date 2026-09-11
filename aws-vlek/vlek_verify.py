#!/usr/bin/env python3
"""Independent check of AWS SEV-SNP probe runs (VLEK-signed reports), without snpguest.

For every runs/<instance>/<stamp>/ directory:
  1. parse the 1184-byte ATTESTATION_REPORT (ABI offsets), including the flags word at 0x48
     (SIGNING_KEY, MASK_CHIP_KEY, AUTHOR_KEY_EN), CHIP_ID at 0x1A0, HOST_DATA at 0xC0,
     REPORT_DATA at 0x50, PLATFORM_INFO, REPORTED_TCB;
  2. verify REPORT_DATA == SHA-512(nonce-sentence.txt) — the public nonce;
  3. verify the ECDSA P-384 signature over bytes [0, 0x2A0) with the VLEK certificate's key;
  4. verify the VLEK certificate against the KDS chain (ASVK → ARK) and list its extensions
     (CSP_ID present? hwID absent?);
  5. compare across runs: same VLEK key in two AZs / two regions or not.
Usage: python3 vlek_verify.py [runs-dir]"""
import sys, glob, os, struct, hashlib, json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils as asn1utils

OID = {"1.3.6.1.4.1.3704.1.1": "structVersion", "1.3.6.1.4.1.3704.1.2": "productName", "1.3.6.1.4.1.3704.1.3.1": "blSPL",
       "1.3.6.1.4.1.3704.1.3.2": "teeSPL", "1.3.6.1.4.1.3704.1.3.3": "snpSPL", "1.3.6.1.4.1.3704.1.3.8": "ucodeSPL",
       "1.3.6.1.4.1.3704.1.4": "hwID", "1.3.6.1.4.1.3704.1.5": "cspID"}

def parse(b):
    f = {}
    f["version"], f["guest_svn"] = struct.unpack_from("<II", b, 0)
    f["policy"] = struct.unpack_from("<Q", b, 8)[0]; f["vmpl"], f["sig_algo"] = struct.unpack_from("<II", b, 0x30)
    f["current_tcb"], f["platform_info"] = struct.unpack_from("<QQ", b, 0x38)
    flags = struct.unpack_from("<I", b, 0x48)[0]
    f["flags"] = {"raw": flags, "author_key_en": flags & 1, "mask_chip_key": (flags >> 1) & 1,
                  "signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7, (flags >> 2) & 7)}
    f["report_data"] = b[0x50:0x90].hex(); f["measurement"] = b[0x90:0xC0].hex(); f["host_data"] = b[0xC0:0xE0].hex()
    f["report_id"] = b[0x140:0x160].hex(); f["reported_tcb"] = struct.unpack_from("<Q", b, 0x180)[0]
    f["chip_id"] = b[0x1A0:0x1E0].hex(); f["chip_id_zero"] = b[0x1A0:0x1E0] == bytes(64)
    f["signature_r"] = b[0x2A0:0x2A0 + 72][:48][::-1].hex(); f["signature_s"] = b[0x2A0 + 72:0x2A0 + 144][:48][::-1].hex()
    return f

def exts(cert):
    out = {}
    for e in cert.extensions:
        name = OID.get(e.oid.dotted_string, e.oid.dotted_string)
        v = getattr(e.value, "value", None)
        out[name] = v.hex() if isinstance(v, bytes) else str(v)
    return out

def verify_sig(report, cert):
    """ECDSA P-384 over the first 0x2A0 bytes; R and S are 72-byte little-endian fields in the ABI."""
    r = int.from_bytes(report[0x2A0:0x2A0 + 48], "little"); s = int.from_bytes(report[0x2A0 + 72:0x2A0 + 72 + 48], "little")
    try: cert.public_key().verify(asn1utils.encode_dss_signature(r, s), report[:0x2A0], ec.ECDSA(hashes.SHA384())); return True
    except Exception: return False

def verify_cert(child, parent):
    pk = parent.public_key()
    if isinstance(pk, rsa.RSAPublicKey):   # ARK and ASK/ASVK: RSA-4096 with PSS, SHA-384
        pk.verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters, child.signature_hash_algorithm)
    else:
        pk.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))

def chain_ok(leaf, chain_pem):
    certs = x509.load_pem_x509_certificates(chain_pem); ok = []   # certs[0] = ASVK (vlek chain) or ASK (vcek chain), certs[1] = ARK
    for child, parent, label in ((leaf, certs[0], "leaf<-ASVK/ASK"), (certs[0], certs[1], "ASVK/ASK<-ARK"), (certs[1], certs[1], "ARK self-signed")):
        try: verify_cert(child, parent); ok.append((label, True, child.subject.rfc4514_string()))
        except Exception as e: ok.append((label, False, repr(e)[:80]))
    return ok

def main(root):
    runs = sorted(glob.glob(os.path.join(root, "*", "*", "report.bin"))); summary = []
    for rp in runs:
        d = os.path.dirname(rp); rep = open(rp, "rb").read(); f = parse(rep)
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l)
        sent = open(os.path.join(d, "nonce-sentence.txt")).read(); nonce_ok = hashlib.sha512(sent.encode()).hexdigest() == f["report_data"]
        leafp = os.path.join(d, "certs", "vlek.pem") if os.path.exists(os.path.join(d, "certs", "vlek.pem")) else os.path.join(d, "certs", "vcek.pem")
        leaf = x509.load_pem_x509_certificate(open(leafp, "rb").read()); e = exts(leaf)
        chainp = os.path.join(d, "kds-vlek-cert_chain.pem" if "vlek" in leafp else "kds-vcek-cert_chain.pem")
        chain = chain_ok(leaf, open(chainp, "rb").read()) if os.path.exists(chainp) else []
        sig = verify_sig(rep, leaf)
        rep2 = os.path.join(d, "report-2.bin"); f2 = parse(open(rep2, "rb").read()) if os.path.exists(rep2) else None
        moved = [k for k in ("report_id", "measurement", "host_data", "chip_id", "reported_tcb") if f2 and f2[k] != f[k]] if f2 else None
        row = {"instance": meta.get("instance-id"), "az": meta.get("az"), "type": meta.get("type"), "captured": meta.get("captured"),
               "signing_key": f["flags"]["signing_key"], "mask_chip_key": f["flags"]["mask_chip_key"], "chip_id_zero": f["chip_id_zero"],
               "chip_id_prefix": f["chip_id"][:16], "host_data": f["host_data"], "nonce_matches_public_sentence": nonce_ok,
               "report_sig_ok": sig, "leaf": os.path.basename(leafp), "leaf_subject": leaf.subject.rfc4514_string(), "leaf_exts": e,
               "leaf_pubkey_sha256": hashlib.sha256(leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16],
               "chain": chain, "fields_that_moved_between_two_reports": moved}
        summary.append(row); print(json.dumps(row, indent=1))
    keys = {}
    for r in summary: keys.setdefault(r["leaf_pubkey_sha256"], []).append(r["az"])
    print("\nVLEK/VCEK public keys seen (key fingerprint -> placements):", json.dumps(keys, indent=1))
    json.dump(summary, open(os.path.join(root, "summary.json"), "w"), indent=1)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
