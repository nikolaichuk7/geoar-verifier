#!/usr/bin/env python3
"""Offline verification of a bound-platform-statement run on Google (probe-bind-gcp.sh), runs/<name>/<stamp>/.

Checks on the operator's machine: the three SEV-SNP reports verify under the VCEK that AMD KDS issues for
their CHIP_ID and TCB (hwID == CHIP_ID, chain to ARK-Milan); r0.REPORT_DATA == SHA-512(sentence);
r-ek.REPORT_DATA == SHA-512(N || SHA-256(EK certificate)); r-jwt.REPORT_DATA == SHA-512(N || SHA-256(token));
the EK certificate verifies under Google's EK/AK CA (fetched via AIA) and names the zone in its subject
and in extension 1.3.6.1.4.1.11129.2.1.21; the identity token verifies under Google's JWKS and names the
same zone. Writes runs/bind-summary.json."""
import sys, os, glob, json, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aws-vlek"))
from dual_verify import parse, sig_ok, chain_ok, load_cert, get
import gcp_verify
from cryptography import x509

def find_zone(obj, zone):
    """True if the string `zone` appears as a value anywhere in a nested dict/list."""
    if isinstance(obj, dict): return any(find_zone(v, zone) for v in obj.values())
    if isinstance(obj, list): return any(find_zone(v, zone) for v in obj)
    return isinstance(obj, str) and obj.rstrip("/").endswith(zone)

def main(root):
    out = []
    try: chain = x509.load_pem_x509_certificates(get("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"))
    except Exception: chain = None
    for d in sorted(glob.glob(os.path.join(root, "*", "2026*"))):
        if not os.path.exists(os.path.join(d, "bind-results.json")): continue
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l); zone = meta.get("zone")
        N = hashlib.sha512(open(os.path.join(d, "nonce-sentence.txt")).read().encode()).digest()
        ek = open(os.path.join(d, "ek-rsa.der"), "rb").read() if os.path.exists(os.path.join(d, "ek-rsa.der")) else b""
        jwt = open(os.path.join(d, "gce-identity-token.jwt"), "rb").read()
        r = {"run": d, "instance": meta.get("instance"), "zone": zone, "reports": {}}
        vcek = None
        for name in ("r0", "r-ek", "r-jwt"):
            p = os.path.join(d, f"report-{name}.bin")
            if not os.path.exists(p): continue
            rep = open(p, "rb").read()[:1184]; f = parse(rep); bl, tee, snp, uc = f["tcb"]
            if vcek is None:
                try: vcek = load_cert(get(f"https://kdsintf.amd.com/vcek/v1/Milan/{f['chip_id']}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}"))
                except Exception as e: r["kds_error"] = repr(e)[:80]
            hw = [e for e in vcek.extensions if e.oid.dotted_string == "1.3.6.1.4.1.3704.1.4"] if vcek else []
            expect = {"r0": N, "r-ek": hashlib.sha512(N + hashlib.sha256(ek).digest()).digest() if ek else None, "r-jwt": hashlib.sha512(N + hashlib.sha256(jwt).digest()).digest()}[name]
            r["reports"][name] = {"signing_key": f["signing_key"], "chip_id_prefix": f["chip_id"][:16], "report_id": f["report_id"][:16],
                                  "signature_ok_with_kds_vcek": sig_ok(rep, vcek) if vcek else None, "vcek_chain_to_ark_ok": chain_ok(vcek, chain) if (vcek and chain) else None,
                                  "hwid_equals_chip_id": hw[0].value.value[-64:].hex() == f["chip_id"] if hw else None, "report_data_binding_ok": rep[0x50:0x90] == expect if expect else None}
        if ek:
            try: r["ek_certificate"] = gcp_verify.ek_verify(d, os.path.join(d, "ek-rsa.der"))
            except Exception as e: r["ek_certificate"] = {"error": repr(e)[:120]}
            r["ek_names_zone"] = find_zone(r["ek_certificate"], zone)
        try: r["identity_token"] = gcp_verify.jwt_verify(os.path.join(d, "gce-identity-token.jwt"))
        except Exception as e: r["identity_token"] = {"error": repr(e)[:120]}
        r["token_names_zone"] = find_zone(r["identity_token"], zone)
        out.append(r); print(json.dumps(r, indent=1, default=str))
    json.dump(out, open(os.path.join(root, "bind-summary.json"), "w"), indent=1, default=str)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
