#!/usr/bin/env python3
"""Offline verification of dual-key / key-selection probe runs (runs/<instance>/<stamp>/).

For every report-*.bin in a run: parse the ABI fields, find the certificate that verifies its
ECDSA P-384 signature (the VLEK or VCEK from the hypervisor's certificate table if present,
else the VCEK fetched from AMD KDS by CHIP_ID and TCB), verify that certificate's chain to
ARK-Milan (VLEK via SEV-VLEK-Milan, VCEK via SEV-Milan), and check the bindings the probe
constructed: REPORT_DATA == SHA-512(sentence) for the plain requests, chB.REPORT_DATA ==
SHA-512(chA bytes) for the chained pair, cb.REPORT_DATA == SHA-512(nonce || SPKI) and the
Ed25519 signature over the nonce for the channel-binding demo. Writes runs/dual-summary.json."""
import sys, os, glob, json, struct, hashlib, urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, utils as asn1utils

UA = {"User-Agent": "geoar-verifier/1.0 (+https://github.com/nikolaichuk7/geoar-verifier)"}
def get(url): return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read()
def load_cert(b):
    return x509.load_pem_x509_certificate(b) if b[:10] == b"-----BEGIN" else x509.load_der_x509_certificate(b)
def product(rep):
    """KDS product name from the CPUID family/model the firmware writes into report version 3 and later (0x188, 0x189);
    older reports carry no such field and are taken as Milan, the only product in the earlier runs."""
    ver = struct.unpack_from("<I", rep, 0)[0]
    if ver < 3: return "Milan"
    fam, mod = rep[0x188], rep[0x189]
    if fam == 0x19 and mod <= 0x0f: return "Milan"
    if fam == 0x19 and 0x10 <= mod <= 0x1f: return "Genoa"
    if fam == 0x1a: return "Turin"
    return "Milan"
def parse(rep):
    flags = struct.unpack_from("<I", rep, 0x48)[0]; tcb = struct.unpack_from("<Q", rep, 0x180)[0]
    return {"signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7, (flags >> 2) & 7), "mask_chip_key": (flags >> 1) & 1, "chip_id": rep[0x1A0:0x1E0].hex(),
            "chip_id_zero": rep[0x1A0:0x1E0] == bytes(64), "report_id": rep[0x140:0x160].hex(), "measurement": rep[0x90:0xC0].hex(), "report_data": rep[0x50:0x90].hex(),
            "tcb": (tcb & 0xff, (tcb >> 8) & 0xff, (tcb >> 48) & 0xff, (tcb >> 56) & 0xff), "product": product(rep), "version": struct.unpack_from("<I", rep, 0)[0]}
def sig_ok(rep, cert):
    r = int.from_bytes(rep[0x2A0:0x2A0 + 48], "little"); s = int.from_bytes(rep[0x2A0 + 72:0x2A0 + 120], "little")
    try: cert.public_key().verify(asn1utils.encode_dss_signature(r, s), rep[:0x2A0], ec.ECDSA(hashes.SHA384())); return True
    except Exception: return False
def chain_ok(leaf, chain):
    try:
        for child, parent in ((leaf, chain[0]), (chain[0], chain[1]), (chain[1], chain[1])):
            pk = parent.public_key()
            if isinstance(pk, rsa.RSAPublicKey): pk.verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters, child.signature_hash_algorithm)
            else: pk.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        return True
    except Exception: return False

def main(root):
    summary = []
    chains = {}
    kds_cache = {}
    def chain_for(kind, prod):
        key = (kind, prod)
        if key not in chains:
            try: chains[key] = x509.load_pem_x509_certificates(get(f"https://kdsintf.amd.com/{kind}/v1/{prod}/cert_chain"))
            except Exception: chains[key] = None
        return chains[key]
    for d in sorted(glob.glob(os.path.join(root, "*", "2026*"))):
        if not glob.glob(os.path.join(d, "report-*.bin")): continue
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l)
        sent = open(os.path.join(d, "nonce-sentence.txt")).read(); N = hashlib.sha512(sent.encode()).digest()
        host_certs = {}
        for p in glob.glob(os.path.join(d, "cert-*.bin")):
            try: host_certs[os.path.basename(p)[5:-4]] = load_cert(open(p, "rb").read())
            except Exception: pass
        for p in glob.glob(os.path.join(d, "certs", "*.pem")):
            try: host_certs[os.path.basename(p)[:-4].upper()] = load_cert(open(p, "rb").read())
            except Exception: pass
        run = {"run": d, "cloud": meta.get("cloud", "aws"), "instance": meta.get("instance") or meta.get("instance-id"), "zone": meta.get("zone") or meta.get("az"), "host_certs": sorted(host_certs), "reports": {}}
        reps = {}
        for p in sorted(glob.glob(os.path.join(d, "report-*.bin"))):
            name = os.path.basename(p)[7:-4]; rep = open(p, "rb").read()[:1184]; f = parse(rep); reps[name] = rep
            r = {"signing_key": f["signing_key"], "product": f["product"], "report_version": f["version"], "chip_id_zero": f["chip_id_zero"], "chip_id_prefix": f["chip_id"][:16], "report_id": f["report_id"][:16], "report_data_is_nonce": f["report_data"] == N.hex()}
            # which certificate verifies the signature
            verified_by = None
            for label, cert in host_certs.items():
                if sig_ok(rep, cert): verified_by = f"host:{label}"; leaf = cert; break
            if verified_by is None and not f["chip_id_zero"]:
                bl, tee, snp, uc = f["tcb"]
                # one fetch per chip and TCB: AMD KDS rate-limits, and every report of a run shares the same certificate
                ck = (f["product"], f["chip_id"], f["tcb"])
                if ck not in kds_cache:
                    try: kds_cache[ck] = load_cert(get(f"https://kdsintf.amd.com/vcek/v1/{f['product']}/{f['chip_id']}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}"))
                    except Exception as e: kds_cache[ck] = None; r["kds_error"] = repr(e)[:80]
                vcek = kds_cache[ck]
                if vcek is not None and sig_ok(rep, vcek): verified_by = "kds:VCEK"; leaf = vcek
            r["verified_by"] = verified_by
            if verified_by:
                kind = "vlek" if f["signing_key"] == "VLEK" else "vcek"; ch = chain_for(kind, f["product"])
                r["chain_ok"] = chain_ok(leaf, ch) if ch else None; r["chain"] = [c.subject.rfc4514_string().split(",")[0] for c in (leaf,) + tuple(ch)] if ch else None
                csp = [e for e in leaf.extensions if e.oid.dotted_string == "1.3.6.1.4.1.3704.1.5"]; hw = [e for e in leaf.extensions if e.oid.dotted_string == "1.3.6.1.4.1.3704.1.4"]
                if csp: r["csp_id"] = csp[0].value.value[2:].decode(errors="replace")
                if hw: r["hwid_equals_chip_id"] = hw[0].value.value[-64:].hex() == f["chip_id"]
            run["reports"][name] = r
        if "chA" in reps and "chB" in reps:
            run["chained"] = {"chB_report_data_is_sha512_chA": parse(reps["chB"])["report_data"] == hashlib.sha512(reps["chA"]).hexdigest(), "same_report_id": parse(reps["chA"])["report_id"] == parse(reps["chB"])["report_id"],
                              "same_measurement": parse(reps["chA"])["measurement"] == parse(reps["chB"])["measurement"], "keys": (parse(reps["chA"])["signing_key"], parse(reps["chB"])["signing_key"])}
        if "cb" in reps and os.path.exists(os.path.join(d, "eph-pub.der")):
            spki = open(os.path.join(d, "eph-pub.der"), "rb").read(); sig = open(os.path.join(d, "eph-sig.bin"), "rb").read() if os.path.exists(os.path.join(d, "eph-sig.bin")) else b""
            cb = {"report_data_is_sha512_nonce_spki": parse(reps["cb"])["report_data"] == hashlib.sha512(N + spki).hexdigest()}
            try: serialization.load_der_public_key(spki).verify(sig, N); cb["ephemeral_sig_over_nonce_ok"] = True
            except Exception as e: cb["ephemeral_sig_over_nonce_ok"] = False
            run["channel_binding"] = cb
        if os.path.exists(os.path.join(d, "dual-results.json")):
            dr = json.load(open(os.path.join(d, "dual-results.json"))); run["firmware"] = {k: {x: v.get(x) for x in ("ok", "ioctl_error", "exitinfo2", "fw_status")} for k, v in dr.items() if isinstance(v, dict) and "key_sel" in v}
            run["ext_report"] = dr.get("ext_report")
        if os.path.exists(os.path.join(d, "keysel-results.json")):
            run["firmware"] = {r["label"]: {x: r.get(x) for x in ("ok", "ioctl_error", "exitinfo2", "fw_status", "signing_key")} for r in json.load(open(os.path.join(d, "keysel-results.json")))}
        summary.append(run); print(json.dumps(run, indent=1, default=str))
    json.dump(summary, open(os.path.join(root, "dual-summary.json"), "w"), indent=1, default=str)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
