#!/usr/bin/env python3
"""Protocol 1: the record a verifier keeps per attested machine, built from every run in this repository.

For each run directory (<cloud>/runs/<name>/<stamp>/) that holds SEV-SNP reports (1184 bytes, version 2-5):
cloud, run, capture time, signing key, CHIP_ID, the SPKI SHA-256 of the key that verifies the reports
(the VCEK that AMD KDS issues for CHIP_ID and TCB, fetched live; or the VLEK the hypervisor supplied),
REPORTED_TCB, REPORT_ID, MEASUREMENT, number of reports, and for VLEK the CSP_ID. Then the same rows
grouped by CHIP_ID, so that a machine seen again is visible. Writes LEDGER.md and ledger.json at the root."""
import os, sys, glob, struct, json, hashlib, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aws-vlek"))
from dual_verify import parse, sig_ok, load_cert, get
from cryptography.hazmat.primitives import serialization

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
def spki_sha256(cert): return hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
def csp_id(cert):
    e = [x for x in cert.extensions if x.oid.dotted_string == "1.3.6.1.4.1.3704.1.5"]; return e[0].value.value[2:].decode(errors="replace") if e else None

def main():
    rows = []; kds_cache = {}
    for cloud in ("gcp-cvm", "azure-cvm", "aws-vlek"):
        for d in sorted(glob.glob(os.path.join(ROOT, cloud, "runs", "*", "2026*"))):
            reps = []
            for p in sorted(glob.glob(os.path.join(d, "**", "*.bin"), recursive=True)):
                b = open(p, "rb").read()
                if len(b) == 1184 and struct.unpack_from("<I", b, 0)[0] in (2, 3, 4, 5): reps.append((p, b))
            if not reps: continue
            name = os.path.basename(os.path.dirname(d)); stamp = os.path.basename(d); f = parse(reps[0][1]); bl, tee, snp, uc = f["tcb"]
            row = {"cloud": cloud.split("-")[0], "run": name, "captured": f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[9:11]}:{stamp[11:13]}Z", "signing_key": f["signing_key"], "chip_id": f["chip_id"],
                   "reported_tcb": f"{bl}.{tee}.{snp}.{uc}", "report_id": f["report_id"], "measurement": f["measurement"], "reports": len(reps),
                   "distinct_chip_ids_in_run": len({parse(b)["chip_id"] for _, b in reps}), "distinct_report_ids_in_run": len({parse(b)["report_id"] for _, b in reps})}
            cert = None
            if f["signing_key"] == "VCEK" and not f["chip_id_zero"]:
                key = (f["chip_id"], f["tcb"])
                if key not in kds_cache:
                    try: kds_cache[key] = load_cert(get(f"https://kdsintf.amd.com/vcek/v1/Milan/{f['chip_id']}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={uc}"))
                    except Exception as e: kds_cache[key] = None; row["kds_error"] = repr(e)[:60]
                cert = kds_cache[key]; row["key_source"] = "AMD KDS by CHIP_ID and TCB"
            else:
                for cp in glob.glob(os.path.join(d, "cert-VLEK.bin")) + glob.glob(os.path.join(d, "certs", "vlek.pem")) + glob.glob(os.path.join(d, "cert-*.bin")):
                    try:
                        c = load_cert(open(cp, "rb").read().rstrip(b"\0"))
                        if sig_ok(reps[0][1], c): cert = c; row["key_source"] = "hypervisor certificate table"; break
                    except Exception: pass
            if cert is not None:
                row["key_spki_sha256"] = spki_sha256(cert); row["signature_ok"] = all(sig_ok(b, cert) for _, b in reps); row["csp_id"] = csp_id(cert)
            rows.append(row); print(row["cloud"], row["run"], row["signing_key"], row["chip_id"][:16], row.get("key_spki_sha256", "")[:16], row.get("signature_ok"))
    json.dump(rows, open(os.path.join(ROOT, "ledger.json"), "w"), indent=1)
    by_chip = collections.OrderedDict()
    for r in rows:
        if r["signing_key"] == "VCEK": by_chip.setdefault(r["chip_id"], []).append(r)
    L = ["# Ledger: the per-machine record a verifier keeps (protocol 1)", "",
         "One row per run that produced SEV-SNP reports. `key` is the SPKI SHA-256 of the certificate that verifies every report of the run: the VCEK that AMD KDS issues for the run's CHIP_ID and TCB (fetched when this table was built), or the VLEK the hypervisor supplied. Full values are in `ledger.json`; the reports themselves are in the run directories.", "",
         "| cloud | run | captured (UTC) | key | CHIP_ID | key SPKI SHA-256 | TCB bl.tee.snp.ucode | REPORT_ID | reports | signatures |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['cloud']} | {r['run']} | {r['captured']} | {r['signing_key']}{' (' + r['csp_id'] + ')' if r.get('csp_id') else ''} | {'all zeros' if set(r['chip_id']) == {'0'} else r['chip_id'][:16] + '…'} | {r.get('key_spki_sha256', '?')[:16]}… | {r['reported_tcb']} | {r['report_id'][:16]}… | {r['reports']} | {'OK' if r.get('signature_ok') else r.get('signature_ok')} |")
    L += ["", f"## Machines seen more than once ({len(by_chip)} distinct CHIP_ID values across {sum(len(v) for v in by_chip.values())} VCEK-signed runs)", "", "| CHIP_ID | runs (captured) |", "|---|---|"]
    for cid, rs in by_chip.items():
        L.append(f"| {cid[:16]}… | " + "; ".join(f"{r['run']} ({r['captured']})" for r in rs) + " |")
    L += ["", "Reading: a CHIP_ID that comes back in a later run is the same machine seen again (the KDS certificate for it verifies both runs' reports); a run whose reports show two CHIP_ID values would be a VM that moved between reports (none so far). REPORT_ID is per guest and changes at every launch, CHIP_ID does not."]
    open(os.path.join(ROOT, "LEDGER.md"), "w").write("\n".join(L) + "\n"); print("LEDGER.md written:", len(rows), "runs,", len(by_chip), "distinct chips")

if __name__ == "__main__": main()
