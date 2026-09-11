#!/usr/bin/env python3
"""Offline verification of an identity-document binding run (probe-idbind.sh), runs/<instance>/<stamp>/.

Checks, on the operator's machine: (1) the EC2 instance identity document verifies under the PKCS#7
signature IMDS served for it, against the certificates AWS publishes for the document's region;
(2) the detached RSA-2048 signature verifies too, where the region publishes an RSA certificate;
(3) the SEV-SNP report's REPORT_DATA == SHA-512(nonce || SHA-256(document)); (4) the report's ECDSA
P-384 signature verifies against the VLEK the hypervisor handed over, and that VLEK chains to
ARK-Milan through SEV-VLEK-Milan from AMD KDS; (5) the VLEK's CSP_ID names the document's region.
The identity document carries the account id, so it stays out of the repository; this script prints
only region, availability zone and instance id. Writes runs/idbind-summary.json."""
import sys, os, glob, json, re, html, hashlib, struct, subprocess, tempfile, base64
from dual_verify import parse, sig_ok, chain_ok, load_cert, get
from cryptography import x509

DOCS = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html"
REGION_NAMES = {"us-east-2": "US East (Ohio)", "us-east-1": "US East (N. Virginia)", "eu-west-1": "Europe (Ireland)", "us-west-2": "US West (Oregon)"}

def region_certs(region):
    page = html.unescape(get(DOCS).decode(errors="replace")); name = REGION_NAMES.get(region, region)
    i = page.find(name); j = page.find("<h3", i + 1) if i >= 0 else -1
    seg = page[i:j] if j > 0 else page[i:i + 8000]
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", seg, re.S)

def openssl(args, stdin=None):
    p = subprocess.run(["openssl"] + args, input=stdin, capture_output=True); return p.returncode == 0, (p.stdout + p.stderr).decode(errors="replace").strip()

def main(root):
    out = []; chain = None
    try: chain = x509.load_pem_x509_certificates(get("https://kdsintf.amd.com/vlek/v1/Milan/cert_chain"))
    except Exception: pass
    for d in sorted(glob.glob(os.path.join(root, "*", "2026*"))):
        if not os.path.exists(os.path.join(d, "report-idbind.bin")): continue
        meta = dict(l.split("=", 1) for l in open(os.path.join(d, "metadata.txt")).read().split() if "=" in l)
        doc = open(os.path.join(d, "identity-document.json"), "rb").read(); dj = json.loads(doc); region = dj["region"]
        rep = open(os.path.join(d, "report-idbind.bin"), "rb").read()[:1184]; f = parse(rep)
        N = hashlib.sha512(open(os.path.join(d, "nonce-sentence.txt")).read().encode()).digest()
        r = {"run": d, "instance": meta.get("instance"), "zone": meta.get("zone"), "document": {"region": region, "availabilityZone": dj.get("availabilityZone"), "instanceId": dj.get("instanceId"), "sha256": hashlib.sha256(doc).hexdigest()},
             "report": {"signing_key": f["signing_key"], "chip_id_zero": f["chip_id_zero"], "report_data_is_sha512_nonce_docdigest": rep[0x50:0x90] == hashlib.sha512(N + hashlib.sha256(doc).digest()).digest()}}
        certs = region_certs(region); r["aws_region_certificates_found"] = len(certs)
        with tempfile.TemporaryDirectory() as t:
            p7 = os.path.join(t, "doc.p7"); open(p7, "w").write("-----BEGIN PKCS7-----\n" + open(os.path.join(d, "identity-pkcs7.b64")).read().strip() + "\n-----END PKCS7-----\n")
            docp = os.path.join(d, "identity-document.json"); r["pkcs7"] = []; r["rsa2048"] = []
            for k, pem in enumerate(certs):
                cp = os.path.join(t, f"c{k}.pem"); open(cp, "w").write(pem + "\n"); c = x509.load_pem_x509_certificate(pem.encode())
                alg = c.signature_algorithm_oid._name; ok, msg = openssl(["smime", "-verify", "-in", p7, "-inform", "PEM", "-content", docp, "-certfile", cp, "-noverify", "-out", "/dev/null"])
                if ok: r["pkcs7"].append({"cert": k, "cert_signature_algorithm": alg, "verified": True})
                if "rsa" in alg.lower():
                    pub = os.path.join(t, f"p{k}.pem"); openssl(["x509", "-in", cp, "-pubkey", "-noout", "-out", pub])
                    sig = os.path.join(t, "doc.sig"); open(sig, "wb").write(base64.b64decode(re.sub(r"\s", "", open(os.path.join(d, "identity-rsa2048.b64")).read())))
                    ok2, msg2 = openssl(["dgst", "-sha256", "-verify", pub, "-signature", sig, docp])
                    if ok2: r["rsa2048"].append({"cert": k, "verified": True})
        vlek_b = open(os.path.join(d, "cert-VLEK.bin"), "rb").read().rstrip(b"\0"); vlek = load_cert(vlek_b)
        r["vlek"] = {"report_signature_ok": sig_ok(rep, vlek), "chain_to_ark_ok": chain_ok(vlek, chain) if chain else None}
        csp = [e for e in vlek.extensions if e.oid.dotted_string == "1.3.6.1.4.1.3704.1.5"]
        r["vlek"]["csp_id"] = csp[0].value.value[2:].decode(errors="replace") if csp else None
        r["vlek"]["csp_id_names_document_region"] = bool(csp) and region in r["vlek"]["csp_id"]
        out.append(r); print(json.dumps(r, indent=1))
    json.dump(out, open(os.path.join(root, "idbind-summary.json"), "w"), indent=1)

if __name__ == "__main__": main(sys.argv[1] if len(sys.argv) > 1 else "runs")
