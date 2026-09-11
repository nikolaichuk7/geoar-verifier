#!/usr/bin/env python3
"""Offline verification of Nitro Enclaves attestation documents captured by probe-nitro.sh (runs/<instance>/<stamp>/).

For every doc-*.cbor: decode the COSE_Sign1 (cbor2), read the payload (module_id, timestamp, digest, pcrs,
certificate, cabundle, public_key, user_data, nonce), fetch the AWS Nitro Enclaves root certificate from AWS
and print its SHA-256 (compare with the value AWS publishes), verify the chain leaf <- cabundle <- root, verify
the ES384 signature with the leaf key (pycose), check that the nonce is the SHA-512 of the public sentence,
that public_key/user_data are what the enclave sent, and that the Ed25519 signature over the nonce verifies
under the bound public key. COSE_Sign1 is verified by hand: Sig_structure = ["Signature1", protected, b"", payload],
signature r||s (96 bytes, P-384), ECDSA-SHA384 under the leaf certificate's key. Then list every place-bearing string in the certificates (subject, SAN, issuer).
Writes runs/nitro-summary.json."""
import sys, os, glob, json, hashlib, io, zipfile, urllib.request, re
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asn1utils

ROOT_ZIP = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
def get(url): return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "geoar-verifier/1.0"}), timeout=40).read()
def root_cert():
    z = zipfile.ZipFile(io.BytesIO(get(ROOT_ZIP))); pem = [z.read(n) for n in z.namelist() if n.endswith(".pem")][0]
    return x509.load_pem_x509_certificate(pem)
def chain_ok(leaf, bundle, root):
    chain = [leaf] + list(reversed(bundle))  # cabundle is root-first; walk leaf -> ... -> root
    try:
        for child, parent in zip(chain, chain[1:] + [root]):
            parent.public_key().verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        return chain[-1].fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()) or bundle[0].fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256())
    except Exception as e: return False
def places(cert):
    out = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string()}
    try: out["san"] = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except Exception: pass
    return out

def main(root_dir):
    root = root_cert(); summary = []
    print("AWS Nitro Enclaves Root G1 SHA-256:", root.fingerprint(hashes.SHA256()).hex())
    for d in sorted(glob.glob(os.path.join(root_dir, "*", "2026*"))):
        docs = sorted(glob.glob(os.path.join(d, "doc-*.cbor")))
        if not docs: continue
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l)
        N = hashlib.sha512(open(os.path.join(d, "nonce-sentence.txt")).read().encode()).digest()
        spki = open(os.path.join(d, "eph-pub.der"), "rb").read() if os.path.exists(os.path.join(d, "eph-pub.der")) else None
        sig = open(os.path.join(d, "eph-sig.bin"), "rb").read() if os.path.exists(os.path.join(d, "eph-sig.bin")) else None
        run = {"run": d, "instance": meta.get("instance"), "zone": meta.get("zone"), "docs": {}}
        for p in docs:
            name = os.path.basename(p)[:-5]; raw = open(p, "rb").read(); r = {"bytes": len(raw)}
            try:
                obj = cbor2.loads(raw); obj = obj.value if isinstance(obj, cbor2.CBORTag) else obj   # Nitro documents are untagged COSE_Sign1 arrays
                protected, unprotected, payload_b, signature = obj; payload = cbor2.loads(payload_b); phdr = cbor2.loads(protected)
            except Exception as e:
                r["error"] = f"not a COSE_Sign1 document: {e!r}"[:160]; run["docs"][name] = r; continue
            r["cose_alg"] = phdr.get(1)
            leaf = x509.load_der_x509_certificate(payload["certificate"]); bundle = [x509.load_der_x509_certificate(c) for c in payload["cabundle"]]
            sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_b]); half = len(signature) // 2
            der = asn1utils.encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
            try: leaf.public_key().verify(der, sig_structure, ec.ECDSA(hashes.SHA384())); r["signature_ok"] = True
            except Exception as e: r["signature_ok"] = False; r["sig_error"] = repr(e)[:100]
            r["chain_to_aws_root_ok"] = chain_ok(leaf, bundle, root)
            r.update({"module_id": payload.get("module_id"), "timestamp": payload.get("timestamp"), "digest": payload.get("digest"),
                      "pcr0": payload["pcrs"][0].hex()[:16] + "…", "pcrs_zero": all(v == bytes(len(v)) for k, v in payload["pcrs"].items() if k in (0, 1, 2)),
                      "nonce_is_sha512_sentence": payload.get("nonce") == N, "user_data": (payload.get("user_data") or b"").decode(errors="replace")[:80] or None,
                      "public_key_is_enclave_spki": (payload.get("public_key") == spki) if payload.get("public_key") else None,
                      "leaf": places(leaf), "chain_subjects": [c.subject.rfc4514_string() for c in bundle]})
            if name == "doc-bound" and spki and sig:
                try: serialization.load_der_public_key(spki).verify(sig, N); r["ephemeral_sig_over_nonce_ok"] = True
                except Exception: r["ephemeral_sig_over_nonce_ok"] = False
            run["docs"][name] = r
        summary.append(run); print(json.dumps(run, indent=1, default=str))
    json.dump(summary, open(os.path.join(root_dir, "nitro-summary.json"), "w"), indent=1, default=str)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
