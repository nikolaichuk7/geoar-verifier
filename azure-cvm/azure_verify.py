#!/usr/bin/env python3
"""Independent verification of Azure Confidential VM probe runs (runs/<name>/<stamp>/).

  HCL report (TPM NV 0x01400001): locate the SEV-SNP ATTESTATION_REPORT after the 32-byte HCL
     header, parse the ABI fields (signing key, CHIP_ID, HOST_DATA, REPORT_DATA), and check that
     REPORT_DATA binds the runtime-data JSON (SHA-256 of the JSON bytes, as the Azure paravisor
     does), which in turn carries the vTPM AK/EK public keys.
  VCEK: from Azure THIM (thim-vcek.pem + chain); verify report signature and the chain to ARK;
     confirm hwID == CHIP_ID; also fetch the VCEK from AMD KDS for the same CHIP_ID/TCB and
     compare the two certificates byte for byte.
  vTPM quote: verify quote-sig.bin over quote-msg.bin with the AK public key taken from the HCL
     runtime data (HCLAkPub), and that the quote's extraData is our public nonce.
  MAA token: decode, verify RS256 against the provider's JWKS (…/certs), list the claims that
     name the TEE, the region (issuer) and the VM.
  IMDS attested document: PKCS#7 signed by Azure; print the signer and the region claim.
Prints one JSON record per run and writes runs/summary.json."""
import sys, os, glob, json, struct, hashlib, base64, urllib.request, subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils as asn1utils

UA = {"User-Agent": "geoar-verifier/1.0 (+https://github.com/nikolaichuk7/geoar-verifier)"}
def get(url): return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read()
def b64u(s): s += "=" * (-len(s) % 4); return base64.urlsafe_b64decode(s)

def snp_parse(b):
    flags = struct.unpack_from("<I", b, 0x48)[0]
    return {"version": struct.unpack_from("<I", b, 0)[0], "policy": hex(struct.unpack_from("<Q", b, 8)[0]),
            "flags": {"raw": flags, "author_key_en": flags & 1, "mask_chip_key": (flags >> 1) & 1, "signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7, (flags >> 2) & 7)},
            "report_data": b[0x50:0x90].hex(), "measurement": b[0x90:0xC0].hex(), "host_data": b[0xC0:0xE0].hex(), "report_id": b[0x140:0x160].hex(),
            "reported_tcb": struct.unpack_from("<Q", b, 0x180)[0], "chip_id": b[0x1A0:0x1E0].hex(), "chip_id_zero": b[0x1A0:0x1E0] == bytes(64)}

def verify_chain(leaf, chain):
    for child, parent in ((leaf, chain[0]), (chain[0], chain[1]), (chain[1], chain[1])):
        pk = parent.public_key()
        if isinstance(pk, rsa.RSAPublicKey): pk.verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters, child.signature_hash_algorithm)
        else: pk.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    return [c.subject.rfc4514_string().split(",")[0] for c in (leaf,) + tuple(chain)]

def tpm2b_pubkey_from_json(entry):
    """HCL runtime data carries keys as JWK-like {kid, kty:'RSA', e, n} dicts."""
    n = int.from_bytes(b64u(entry["n"]), "big"); e = int.from_bytes(b64u(entry["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()

def main(root):
    summary = []
    for d in sorted(glob.glob(os.path.join(root, "*", "2026*"))):
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l)
        row = {"run": d, "region": meta.get("region"), "size": meta.get("size"), "tee": meta.get("tee"), "captured": meta.get("captured")}
        sent = open(os.path.join(d, "nonce-sentence.txt")).read(); nonce_hex = hashlib.sha512(sent.encode()).hexdigest()
        hcl = open(os.path.join(d, "hcl-report.bin"), "rb").read() if os.path.exists(os.path.join(d, "hcl-report.bin")) else b""
        # HCL layout: 32-byte header {HCLA, version, report_size, request_type, ...}, hardware report (SNP 1184 / TD 1024),
        # then var-data: u32 size, 16-byte sub-header, and the runtime-data JSON whose SHA-256 is the report's REPORT_DATA
        rt = b""
        if hcl[:4] == b"HCLA":
            hw_len = 1184 if struct.unpack_from("<I", hcl, 32)[0] in (2, 3, 4, 5) else 1024
            j0 = hcl.find(b"{", 32 + hw_len); jl = struct.unpack_from("<I", hcl, j0 - 4)[0] if j0 > 0 else 0; rt = hcl[j0:j0 + jl]
            open(os.path.join(d, "hcl-runtime-data.json"), "wb").write(rt)
        row["hcl"] = {"size": len(hcl), "magic": hcl[:4].decode(errors="replace"), "hcl_version": struct.unpack_from("<I", hcl, 4)[0] if hcl else None, "report_size": struct.unpack_from("<I", hcl, 8)[0] if hcl else None, "runtime_data_bytes": len(rt)}
        try: rtj = json.loads(rt); row["hcl"]["runtime_keys"] = list(rtj.keys()); row["hcl"]["vm_configuration"] = rtj.get("vm-configuration")
        except Exception: rtj = {}
        rp = os.path.join(d, "report.bin")
        if os.path.exists(rp):
            rep = open(rp, "rb").read()[:1184]; f = snp_parse(rep); s = {k: f[k] for k in ("version", "policy", "flags", "host_data", "chip_id_zero", "reported_tcb")}
            s["chip_id_prefix"] = f["chip_id"][:16]
            s["report_data_binds_runtime_json"] = f["report_data"][:64] == hashlib.sha256(rt).hexdigest() and f["report_data"][64:] == "0" * 64
            try:
                vcek = x509.load_pem_x509_certificate(open(os.path.join(d, "thim-vcek.pem"), "rb").read()); chain = x509.load_pem_x509_certificates(open(os.path.join(d, "thim-chain.pem"), "rb").read())
                r = int.from_bytes(rep[0x2A0:0x2A0 + 48], "little"); sg = int.from_bytes(rep[0x2A0 + 72:0x2A0 + 120], "little")
                vcek.public_key().verify(asn1utils.encode_dss_signature(r, sg), rep[:0x2A0], ec.ECDSA(hashes.SHA384())); s["report_sig_ok_thim_vcek"] = True
                s["thim_chain"] = verify_chain(vcek, chain); s["thim_chain_ok"] = True
                hw = [e for e in vcek.extensions if e.oid.dotted_string == "1.3.6.1.4.1.3704.1.4"]; s["thim_vcek_hwid_equals_chip_id"] = bool(hw) and hw[0].value.value[-64:].hex() == f["chip_id"]
                tcb = f["reported_tcb"]; bl, tee, snp, uc = tcb & 0xff, (tcb >> 8) & 0xff, (tcb >> 48) & 0xff, (tcb >> 56) & 0xff
                kds = get(f"https://kdsintf.amd.com/vcek/v1/Milan/{f['chip_id']}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}")
                s["kds_vcek_identical_to_thim_vcek"] = kds == vcek.public_bytes(serialization.Encoding.DER)
            except Exception as e: s["vcek_error"] = repr(e)[:160]
            row["snp"] = s
        # vTPM quote over our nonce with the HCL AK
        qm, qs = os.path.join(d, "quote-msg.bin"), os.path.join(d, "quote-sig.bin")
        if os.path.exists(qm) and os.path.exists(qs):
            msg, sig = open(qm, "rb").read(), open(qs, "rb").read(); q = {"attest_len": len(msg)}
            try:
                # TPMS_ATTEST: magic(4) type(2) qualifiedSigner(2+n) extraData(2+n) ...
                assert msg[:4] == b"\xff\x54\x43\x47"; i = 6; n = struct.unpack_from(">H", msg, i)[0]; i += 2 + n; n = struct.unpack_from(">H", msg, i)[0]; extra = msg[i + 2:i + 2 + n]
                q["extra_data_is_our_nonce"] = extra.hex() == nonce_hex[:64] or extra.hex() == nonce_hex
                keys = {k.get("kid"): k for k in rtj.get("keys", [])}; ak = keys.get("HCLAkPub")
                # TPMT_SIGNATURE: sigAlg(2) hashAlg(2) size(2) sig
                alg, halg, sz = struct.unpack_from(">HHH", sig, 0); raw = sig[6:6 + sz]
                if ak: tpm2b_pubkey_from_json(ak).verify(raw, msg, padding.PKCS1v15(), hashes.SHA256()); q["quote_sig_ok_with_HCLAkPub"] = True
                else: q["note"] = "HCLAkPub not found in runtime data"
                q["ak_handle_used"] = open(os.path.join(d, "quote-ak-handle.txt")).read().strip() if os.path.exists(os.path.join(d, "quote-ak-handle.txt")) else None
            except Exception as e: q["error"] = repr(e)[:160]
            row["tpm_quote"] = q
        # MAA token
        mp = os.path.join(d, "maa-token.jwt")
        if os.path.exists(mp) and os.path.getsize(mp) > 0:
            tok = open(mp).read().strip(); h, p = json.loads(b64u(tok.split(".")[0])), json.loads(b64u(tok.split(".")[1]))
            m = {"iss": p.get("iss"), "jku": h.get("jku"), "kid": h.get("kid"), "x-ms-attestation-type": p.get("x-ms-attestation-type"), "x-ms-compliance-status": p.get("x-ms-compliance-status")}
            tee = p.get("x-ms-isolation-tee") or {}; m["tee_claims"] = {k: v for k, v in tee.items() if k in ("x-ms-attestation-type", "x-ms-compliance-status", "x-ms-sevsnpvm-is-debuggable", "x-ms-sevsnpvm-vmpl", "x-ms-sevsnpvm-reportid", "x-ms-sevsnpvm-hostdata")}
            m["azurevm_claims"] = {k: v for k, v in p.items() if k.startswith("x-ms-azurevm-") and k in ("x-ms-azurevm-vmid", "x-ms-azurevm-osdistro", "x-ms-azurevm-attestation-protocol-ver")}
            try:
                jwks = json.loads(get(h.get("jku") or (p["iss"].rstrip("/") + "/certs"))); key = [k for k in jwks["keys"] if k.get("kid") == h.get("kid")][0]
                cert = x509.load_der_x509_certificate(base64.b64decode(key["x5c"][0])); cert.public_key().verify(b64u(tok.split(".")[2]), ".".join(tok.split(".")[:2]).encode(), padding.PKCS1v15(), hashes.SHA256())
                m["sig_ok"] = True; m["signer_cert_subject"] = cert.subject.rfc4514_string()
            except Exception as e: m["sig_check"] = repr(e)[:120]
            row["maa"] = m
        # IMDS attested document (PKCS#7)
        ap = os.path.join(d, "imds-attested-document.json")
        if os.path.exists(ap):
            try:
                doc = json.load(open(ap)); sig = doc["signature"]; der = base64.b64decode(sig)
                open(os.path.join(d, "imds-attested.p7b"), "wb").write(der)
                out = subprocess.run(["openssl", "smime", "-verify", "-inform", "DER", "-in", os.path.join(d, "imds-attested.p7b"), "-noverify"], capture_output=True, text=True, timeout=30)
                payload = json.loads(out.stdout) if out.returncode == 0 else {}
                signer = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", os.path.join(d, "imds-attested.p7b"), "-print_certs", "-noout", "-text"], capture_output=True, text=True, timeout=30).stdout
                subj = [l.strip() for l in signer.splitlines() if "Subject:" in l][:1]
                row["imds_attested"] = {"payload_keys": list(payload.keys()), "region": payload.get("licenseType") and None or (payload.get("plan") or {}), "vmId": payload.get("vmId"), "signer": subj, "encoding": doc.get("encoding")}
                row["imds_attested"]["payload"] = {k: payload[k] for k in payload if k in ("vmId", "sku", "nonce", "timeStamp")}
            except Exception as e: row["imds_attested"] = {"error": repr(e)[:160]}
        summary.append(row); print(json.dumps(row, indent=1, default=str))
    json.dump(summary, open(os.path.join(root, "summary.json"), "w"), indent=1, default=str)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
