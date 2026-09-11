#!/usr/bin/env python3
"""Independent verification of Google Cloud Confidential VM probe runs (runs/<name>/<stamp>/).

For each run:
  SEV-SNP report (report.bin): parse ABI fields, check REPORT_DATA == SHA-512(nonce-sentence.txt),
     fetch the VCEK from AMD KDS by CHIP_ID + reported TCB, verify report signature and chain.
  TDX quote (quote.bin): parse header and TD report body, check REPORTDATA == SHA-512(sentence),
     verify the ECDSA-P256 quote signature with the embedded attestation key, verify the QE report
     binds that key and is signed by the PCK leaf, verify the embedded PCK chain up to Intel's root.
  vTPM EK certificates (ek-*.der): print issuer, fetch the issuer via AIA, verify the signature,
     decode Google's GCE instance extension (OID 1.3.6.1.4.1.11129.2.1.21: zone, project, instance).
  Tokens (gce-identity-token.jwt, gcp-attestation-token.jwt): decode; verify RS256 against the
     issuer's JWKS found through OpenID discovery; print the claims that name a place.
Prints one JSON record per run and writes runs/summary.json."""
import sys, os, glob, json, struct, hashlib, base64, urllib.request, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils as asn1utils

UA = {"User-Agent": "geoar-verifier/1.0 (+https://github.com/nikolaichuk7/geoar-verifier)"}
def get(url, tries=3):
    for i in range(tries):
        try: return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read()
        except Exception as e:
            if i == tries - 1: raise
            time.sleep(2)

def b64u(s): s += "=" * (-len(s) % 4); return base64.urlsafe_b64decode(s)

# ---------- SEV-SNP ----------
def snp_parse(b):
    f = {"version": struct.unpack_from("<I", b, 0)[0], "policy": struct.unpack_from("<Q", b, 8)[0]}
    flags = struct.unpack_from("<I", b, 0x48)[0]
    f["flags"] = {"raw": flags, "author_key_en": flags & 1, "mask_chip_key": (flags >> 1) & 1, "signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7, (flags >> 2) & 7)}
    f["report_data"] = b[0x50:0x90].hex(); f["measurement"] = b[0x90:0xC0].hex(); f["host_data"] = b[0xC0:0xE0].hex()
    f["report_id"] = b[0x140:0x160].hex(); f["reported_tcb"] = struct.unpack_from("<Q", b, 0x180)[0]
    f["chip_id"] = b[0x1A0:0x1E0].hex(); f["chip_id_zero"] = b[0x1A0:0x1E0] == bytes(64)
    return f

def snp_verify(d, rep, f):
    tcb = f["reported_tcb"]; bl, tee, snp, uc = tcb & 0xff, (tcb >> 8) & 0xff, (tcb >> 48) & 0xff, (tcb >> 56) & 0xff
    out = {"signing_key": f["flags"]["signing_key"], "chip_id_zero": f["chip_id_zero"], "chip_id_prefix": f["chip_id"][:16], "host_data": f["host_data"]}
    try:
        prod = "Milan"
        vcek = x509.load_der_x509_certificate(get(f"https://kdsintf.amd.com/vcek/v1/{prod}/{f['chip_id']}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}"))
        chain = x509.load_pem_x509_certificates(get(f"https://kdsintf.amd.com/vcek/v1/{prod}/cert_chain")); ask, ark = chain[0], chain[1]
        open(os.path.join(d, "kds-vcek.der"), "wb").write(vcek.public_bytes(serialization.Encoding.DER))
        r = int.from_bytes(rep[0x2A0:0x2A0 + 48], "little"); s = int.from_bytes(rep[0x2A0 + 72:0x2A0 + 120], "little")
        vcek.public_key().verify(asn1utils.encode_dss_signature(r, s), rep[:0x2A0], ec.ECDSA(hashes.SHA384())); out["report_sig_ok"] = True
        for child, parent, label in ((vcek, ask, "VCEK<-ASK"), (ask, ark, "ASK<-ARK"), (ark, ark, "ARK self")):
            parent.public_key().verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters, child.signature_hash_algorithm)
        out["chain_ok"] = True
        hw = [e for e in vcek.extensions if e.oid.dotted_string == "1.3.6.1.4.1.3704.1.4"]
        out["vcek_hwid_equals_chip_id"] = bool(hw) and hw[0].value.value[-64:].hex() == f["chip_id"]
    except Exception as e: out["error"] = repr(e)[:160]
    return out

# ---------- TDX ----------
def tdx_parse(q):
    h = {"version": struct.unpack_from("<H", q, 0)[0], "att_key_type": struct.unpack_from("<H", q, 2)[0], "tee_type": hex(struct.unpack_from("<I", q, 4)[0]),
         "qe_vendor_id": q[12:28].hex(), "user_data": q[28:48].hex()}
    body = q[48:48 + 584]
    b = {"tee_tcb_svn": body[0:16].hex(), "mrseam": body[16:64].hex(), "seam_attributes": body[112:120].hex(), "td_attributes": body[120:128].hex(), "xfam": body[128:136].hex(),
         "mrtd": body[136:184].hex(), "mrconfigid": body[184:232].hex(), "mrowner": body[232:280].hex(), "mrownerconfig": body[280:328].hex(),
         "rtmr0": body[328:376].hex(), "rtmr1": body[376:424].hex(), "rtmr2": body[424:472].hex(), "rtmr3": body[472:520].hex(), "report_data": body[520:584].hex()}
    sig_len = struct.unpack_from("<I", q, 48 + 584)[0]; sig = q[48 + 584 + 4:48 + 584 + 4 + sig_len]
    s = {"sig": sig[0:64], "ak": sig[64:128], "cert_data_type": struct.unpack_from("<H", sig, 128)[0], "cert_data_size": struct.unpack_from("<I", sig, 130)[0]}
    s["cert_data"] = sig[134:134 + s["cert_data_size"]]
    return h, b, s

def tdx_verify(d, q):
    h, b, s = tdx_parse(q); out = {"header": h, "mrtd": b["mrtd"][:32] + "…", "report_data": b["report_data"], "td_attributes": b["td_attributes"], "cert_data_type": s["cert_data_type"]}
    try:
        ak = ec.EllipticCurvePublicNumbers(int.from_bytes(s["ak"][:32], "big"), int.from_bytes(s["ak"][32:], "big"), ec.SECP256R1()).public_key()
        ak.verify(asn1utils.encode_dss_signature(int.from_bytes(s["sig"][:32], "big"), int.from_bytes(s["sig"][32:], "big")), q[:48 + 584], ec.ECDSA(hashes.SHA256())); out["quote_sig_ok"] = True
        if s["cert_data_type"] == 6:   # QE report certification data: qe_report(384) + qe_sig(64) + auth_size(2) + auth + cert_type(2) + size(4) + PEM chain
            cd = s["cert_data"]; qe_report, qe_sig = cd[:384], cd[384:448]; auth_size = struct.unpack_from("<H", cd, 448)[0]; auth = cd[450:450 + auth_size]
            p = 450 + auth_size; ctype, csize = struct.unpack_from("<HI", cd, p); pem = cd[p + 6:p + 6 + csize]
            out["qe_binds_ak"] = qe_report[320:352] == hashlib.sha256(s["ak"] + auth).digest()
            certs = x509.load_pem_x509_certificates(pem); pck = certs[0]
            pck.public_key().verify(asn1utils.encode_dss_signature(int.from_bytes(qe_sig[:32], "big"), int.from_bytes(qe_sig[32:], "big")), qe_report, ec.ECDSA(hashes.SHA256())); out["qe_report_sig_ok"] = True
            for i in range(len(certs) - 1): certs[i + 1].public_key().verify(certs[i].signature, certs[i].tbs_certificate_bytes, ec.ECDSA(certs[i].signature_hash_algorithm))
            root = certs[-1]; root.public_key().verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(root.signature_hash_algorithm))
            out["pck_chain"] = [c.subject.rfc4514_string() for c in certs]
            intel_root = x509.load_pem_x509_certificate(get("https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"))
            out["root_is_intel_sgx_root"] = root.public_bytes(serialization.Encoding.DER) == intel_root.public_bytes(serialization.Encoding.DER)
            fm = [e for e in pck.extensions if e.oid.dotted_string == "1.2.840.113741.1.13.1"]; out["pck_has_intel_sgx_ext"] = bool(fm)
            open(os.path.join(d, "pck-chain.pem"), "wb").write(pem)
    except Exception as e: out["error"] = repr(e)[:160]
    return out

# ---------- vTPM EK certificate ----------
def pb_decode(buf):
    """Minimal protobuf decoder: returns {field: [values]} with strings decoded when printable."""
    out, i = {}, 0
    def varint():
        nonlocal i; v = sh = 0
        while True:
            c = buf[i]; i += 1; v |= (c & 0x7f) << sh; sh += 7
            if not c & 0x80: return v
    while i < len(buf):
        tag = varint(); fld, wt = tag >> 3, tag & 7
        if wt == 0: val = varint()
        elif wt == 2:
            n = varint(); raw = buf[i:i + n]; i += n
            try: val = raw.decode(); val = val if val.isprintable() else raw.hex()
            except Exception: val = raw.hex()
        elif wt == 1: val = struct.unpack_from("<Q", buf, i)[0]; i += 8
        elif wt == 5: val = struct.unpack_from("<I", buf, i)[0]; i += 4
        else: break
        out.setdefault(fld, []).append(val)
    return out

def der_tlv(buf, i):
    tag = buf[i]; n = buf[i + 1]; j = i + 2
    if n & 0x80: k = n & 0x7f; n = int.from_bytes(buf[j:j + k], "big"); j += k
    return tag, buf[j:j + n], j + n

def der_seq(buf):
    """Decode a DER SEQUENCE of simple values into Python values (UTF8String/IA5/Printable -> str, INTEGER -> int, BOOLEAN -> bool, nested SEQUENCE -> list)."""
    tag, body, _ = der_tlv(buf, 0); assert tag == 0x30, "not a SEQUENCE"
    out, i = [], 0
    while i < len(body):
        t, v, i = der_tlv(body, i)
        if t in (0x0c, 0x16, 0x13): out.append(v.decode(errors="replace"))
        elif t == 0x02: out.append(int.from_bytes(v, "big", signed=True))
        elif t == 0x01: out.append(v != b"\x00")
        elif t == 0x30: out.append(der_seq(bytes([0x30, len(v)]) + v) if len(v) < 128 else "nested")
        else: out.append({"tag": hex(t), "hex": v.hex()})
    return out

def ek_verify(d, path):
    cert = x509.load_der_x509_certificate(open(path, "rb").read())
    out = {"file": os.path.basename(path), "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "not_before": str(cert.not_valid_before_utc)}
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName); out["san"] = [str(n.value)[:120] for n in san.value]
    except Exception: pass
    out["extension_oids"] = [e.oid.dotted_string for e in cert.extensions]
    for e in cert.extensions:
        if e.oid.dotted_string == "1.3.6.1.4.1.11129.2.1.21":
            raw = e.value.value
            if raw[:1] == b"\x04":   # DER OCTET STRING wrapper around the protobuf
                n = raw[1]; raw = raw[2 + (n & 0x7f):] if n & 0x80 else raw[2:]
            out["gce_instance_ext_raw"] = raw.hex()[:120]
            try:   # go-tpm-tools encodes this extension as an ASN.1 SEQUENCE {zone UTF8String, projectId UTF8String, projectNumber INTEGER, instanceName UTF8String, instanceId INTEGER, securityProperties SEQUENCE}
                items = der_seq(raw); names = ["zone", "project_number", "project_id", "instance_id", "instance_name", "security_properties"]   # order as go-tpm-tools encodes it
                out["gce_instance_ext"] = {names[i] if i < len(names) else f"field{i}": v for i, v in enumerate(items)}
            except Exception as ex:
                try: pb = pb_decode(raw); out["gce_instance_ext"] = {"protobuf": pb}
                except Exception: out["gce_instance_ext"] = "decode failed: " + repr(ex)[:80]
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        url = [a.access_location.value for a in aia if a.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"][0]
        raw = get(url); issuer = x509.load_der_x509_certificate(raw) if raw[:1] == b"\x30" else x509.load_pem_x509_certificate(raw)
        pk = issuer.public_key()
        if isinstance(pk, rsa.RSAPublicKey): pk.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        else: pk.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        out["issuer_sig_ok"] = True; out["issuer_of_issuer"] = issuer.issuer.rfc4514_string()
        open(os.path.join(d, os.path.basename(path).replace(".der", "-issuer.der")), "wb").write(issuer.public_bytes(serialization.Encoding.DER))
    except Exception as e: out["issuer_check"] = repr(e)[:120]
    return out

# ---------- JWTs ----------
def jwt_verify(path):
    tok = open(path).read().strip(); parts = tok.split(".")
    if len(parts) != 3: return {"file": os.path.basename(path), "error": "not a JWT: " + tok[:80]}
    hdr, pl = json.loads(b64u(parts[0])), json.loads(b64u(parts[1])); out = {"file": os.path.basename(path), "iss": pl.get("iss"), "alg": hdr.get("alg"), "kid": hdr.get("kid")}
    place = {}
    for k in ("hwmodel", "swname", "dbgstat", "secboot", "eat_profile", "submods", "google", "sub", "aud", "iat", "exp"):
        if k in pl: place[k] = pl[k]
    out["claims"] = place
    try:
        disc = json.loads(get(pl["iss"].rstrip("/") + "/.well-known/openid-configuration")); jwks = json.loads(get(disc["jwks_uri"]))
        key = [k for k in jwks["keys"] if k.get("kid") == hdr.get("kid")][0]
        pub = rsa.RSAPublicNumbers(int.from_bytes(b64u(key["e"]), "big"), int.from_bytes(b64u(key["n"]), "big")).public_key()
        pub.verify(b64u(parts[2]), (parts[0] + "." + parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256()); out["sig_ok"] = True; out["jwks_uri"] = disc["jwks_uri"]
    except Exception as e: out["sig_check"] = repr(e)[:120]
    return out

def main(root):
    summary = []
    for d in sorted(glob.glob(os.path.join(root, "*", "2026*"))):
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l)
        sent = open(os.path.join(d, "nonce-sentence.txt")).read(); nonce = hashlib.sha512(sent.encode()).hexdigest()
        row = {"run": d, "zone": meta.get("zone"), "machine": meta.get("machine-type"), "tee": meta.get("tee"), "captured": meta.get("captured")}
        rp = os.path.join(d, "report.bin")
        if os.path.exists(rp) and os.path.getsize(rp) >= 1184:
            rep = open(rp, "rb").read()[:1184]; f = snp_parse(rep); row["snp"] = snp_verify(d, rep, f); row["snp"]["nonce_ok"] = f["report_data"] == nonce
        qp = os.path.join(d, "quote.bin")
        if os.path.exists(qp) and os.path.getsize(qp) > 700:
            q = open(qp, "rb").read(); row["tdx"] = tdx_verify(d, q); row["tdx"]["nonce_ok"] = row["tdx"]["report_data"] == nonce
        row["ek"] = [ek_verify(d, p) for p in sorted(glob.glob(os.path.join(d, "ek-*.der"))) if os.path.getsize(p) > 0 and "-issuer" not in p]
        row["tokens"] = [jwt_verify(p) for p in sorted(glob.glob(os.path.join(d, "*.jwt"))) if os.path.getsize(p) > 0]
        summary.append(row); print(json.dumps(row, indent=1, default=str))
    json.dump(summary, open(os.path.join(root, "summary.json"), "w"), indent=1, default=str)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
