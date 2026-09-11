#!/usr/bin/env python3
"""Offline checks for a NitroTPM run (probe-nitrotpm.sh), runs/<instance>/<stamp>/ plus runs/<instance>/ekpub-*.der.

1. EK: the guest's TPM2B_PUBLIC (ek.pub, tpm2_createek) versus the EK public key the EC2 control plane returns
   for the same instance (GetInstanceTpmEkPub, DER): same RSA modulus means AWS's API endorses the key the TPM
   in the guest holds; there is no EK certificate in the TPM's NV space to compare with.
2. Quote: quote.sig (TPMT_SIGNATURE, RSASSA/SHA-256) verifies over quote.msg under ak.pub; the TPMS_ATTEST
   extraData equals SHA-256 of the public sentence; PCR selection and digest are printed.
Writes runs/nitrotpm-summary.json."""
import sys, os, glob, json, struct, hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def tpm2b_public_rsa(b):
    """TPM2B_PUBLIC -> (modulus int, exponent). Layout: size(2) type(2) nameAlg(2) attrs(4) authPolicy(2+n) params: symmetric(2[+2+2]) scheme(2[+2]) keyBits(2) exponent(4) unique: size(2) modulus."""
    i = 2; typ, name_alg = struct.unpack_from(">HH", b, i); i += 4; i += 4; pol = struct.unpack_from(">H", b, i)[0]; i += 2 + pol
    if typ != 0x0001: raise ValueError(f"not RSA: type 0x{typ:04x}")
    sym = struct.unpack_from(">H", b, i)[0]; i += 2
    if sym != 0x0010: i += 2 + 2                       # keyBits + mode when symmetric != NULL (EK: AES-128 CFB)
    scheme = struct.unpack_from(">H", b, i)[0]; i += 2
    if scheme != 0x0010: i += 2                         # hash alg of the scheme (AK: RSASSA + SHA-256)
    key_bits = struct.unpack_from(">H", b, i)[0]; i += 2; exp = struct.unpack_from(">I", b, i)[0] or 65537; i += 4
    n = struct.unpack_from(">H", b, i)[0]; i += 2; return int.from_bytes(b[i:i + n], "big"), exp

def main(root):
    out = []
    for d in sorted(glob.glob(os.path.join(root, "*", "2026*"))):
        if not os.path.exists(os.path.join(d, "tpm-properties.txt")): continue
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l); inst = os.path.basename(os.path.dirname(d))
        r = {"run": d, "instance": meta.get("instance"), "zone": meta.get("zone"), "instance_type": meta.get("instance-type")}
        props = open(os.path.join(d, "tpm-properties.txt")).read()
        for k in ("TPM2_PT_MANUFACTURER", "TPM2_PT_VENDOR_STRING_1", "TPM2_PT_VENDOR_STRING_2", "TPM2_PT_FIRMWARE_VERSION_1"):
            j = props.find(k)
            if j >= 0:
                raw = props[j:j + 120].split("raw:")[1].split()[0] if "raw:" in props[j:j + 120] else None
                try: r[k] = bytes.fromhex(raw[2:]).decode(errors="replace") if k != "TPM2_PT_FIRMWARE_VERSION_1" else raw
                except Exception: r[k] = raw
        r["ek_certificate_in_nv"] = os.path.exists(os.path.join(d, "ek-rsa.der")) and os.path.getsize(os.path.join(d, "ek-rsa.der")) > 0
        r["nv_indexes_listed"] = [l.split(":")[0] for l in open(os.path.join(d, "nv-indexes.txt")).read().splitlines() if l.startswith("0x")]
        # 1. EK from the guest vs EK from the EC2 API
        try:
            ek_n, ek_e = tpm2b_public_rsa(open(os.path.join(d, "ek.pub"), "rb").read()); r["guest_ek_modulus_sha256"] = hashlib.sha256(ek_n.to_bytes(256, "big")).hexdigest()[:16]
            api = os.path.join(root, inst, "ekpub-rsa-2048.der")
            if os.path.exists(api):
                pub = serialization.load_der_public_key(open(api, "rb").read()); r["api_ek_modulus_sha256"] = hashlib.sha256(pub.public_numbers().n.to_bytes(256, "big")).hexdigest()[:16]
                r["api_ek_equals_guest_ek"] = pub.public_numbers().n == ek_n
            else: r["api_ek_equals_guest_ek"] = None
        except Exception as e: r["ek_error"] = repr(e)[:100]
        # 2. quote under the AK
        try:
            ak_n, ak_e = tpm2b_public_rsa(open(os.path.join(d, "ak.pub"), "rb").read()); ak = rsa.RSAPublicNumbers(ak_e, ak_n).public_key()
            sig = open(os.path.join(d, "quote.sig"), "rb").read(); msg = open(os.path.join(d, "quote.msg"), "rb").read()
            sig_alg, hash_alg, slen = struct.unpack_from(">HHH", sig, 0); r["quote_sig_alg"] = hex(sig_alg); s = sig[6:6 + slen]
            ak.verify(s, msg, padding.PKCS1v15(), hashes.SHA256()); r["quote_signature_ok"] = True
            # TPMS_ATTEST: magic(4) type(2) qualifiedSigner(2+n) extraData(2+n) clock(8) resetCount(4) restartCount(4) safe(1) attested: pcrSelect + digest
            i = 6; qn = struct.unpack_from(">H", msg, i)[0]; i += 2 + qn; en = struct.unpack_from(">H", msg, i)[0]; i += 2; extra = msg[i:i + en]; i += en + 8 + 4 + 4 + 1 + 8   # clockInfo (17) + firmwareVersion (8)
            nonce256 = bytes.fromhex(open(os.path.join(d, "nonce256.hex")).read().strip()); r["quote_extra_data_is_sha256_sentence"] = extra == nonce256
            cnt = struct.unpack_from(">I", msg, i)[0]; i += 4; sel = []
            for _ in range(cnt):
                alg, sz = struct.unpack_from(">HB", msg, i); i += 3; sel.append((hex(alg), msg[i:i + sz].hex())); i += sz
            dn = struct.unpack_from(">H", msg, i)[0]; i += 2; r["pcr_selection"] = sel; r["pcr_digest"] = msg[i:i + dn].hex()[:16] + "…"
        except Exception as e: r["quote_error"] = repr(e)[:120]; r["quote_signature_ok"] = False
        out.append(r); print(json.dumps(r, indent=1))
    json.dump(out, open(os.path.join(root, "nitrotpm-summary.json"), "w"), indent=1)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
