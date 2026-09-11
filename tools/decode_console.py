#!/usr/bin/env python3
"""Reassemble a probe archive from a serial-console capture and extract it.

Usage: decode_console.py <console.txt> <outdir>   ->  exit 0 only after a SHA-256-verified extraction.

The probe writes the base64 archive as 76-char lines "@@NNNN <b64>", three copies, between
"===PROBE-BEGIN=== <stamp> <id> <zone> <cloud> size=<n> sha256=<hex> lines=<k> copy=<c>" and
"===PROBE-END===". Console output from other writers (cloud-init, journald, the kernel) can land
inside or even in the middle of a line, so lines are taken from any copy, by index, only when they
have the expected length, and the whole base64 must hash to the value the probe printed.
The legacy single-line format (no "@@" lines) is still accepted when its length matches size=."""
import sys, re, base64, io, tarfile, os, hashlib

def decode(text):
    text = re.sub(r"\[\d{4}-\d{2}-\d{2}T[\d:.]+\]", "", text)          # EC2 serial-console timestamps
    heads = list(re.finditer(r"===PROBE-BEGIN=== ([^\n]*?)size=(\d+)(?: sha256=([0-9a-f]{64}) lines=(\d+) copy=(\d+))?", text))
    if not heads: return None, "no BEGIN marker"
    size = int(heads[0].group(2)); sha = heads[0].group(3); nlines = int(heads[0].group(4)) if heads[0].group(4) else None
    if sha:
        cand = {}
        for m in re.finditer(r"@@(\d{4}) ([A-Za-z0-9+/=]+)", text):
            i = int(m.group(1)); want = 76 if i < nlines - 1 else size - 76 * (nlines - 1)
            if len(m.group(2)) == want: cand.setdefault(i, m.group(2))
        missing = [i for i in range(nlines) if i not in cand]
        if missing: return None, f"{len(missing)} of {nlines} lines not yet intact (e.g. {missing[:5]})"
        b64 = "".join(cand[i] for i in range(nlines))
        if len(b64) != size: return None, f"assembled {len(b64)} chars, expected {size}"
        if hashlib.sha256(b64.encode()).hexdigest() != sha: return None, "sha256 mismatch after reassembly"
        return base64.b64decode(b64), f"sha256 verified over {nlines} lines"
    for h in heads:                                                     # legacy format
        end = text.find("===PROBE-END===", h.end()); body = re.sub(r"[^A-Za-z0-9+/=]", "", text[h.end():end if end > 0 else None])
        if len(body) == size: return base64.b64decode(body), "legacy single-line payload, length matched"
    return None, "legacy payload length mismatch in every copy"

def main(console, outdir):
    text = open(console, errors="replace").read()
    data, why = decode(text)
    if data is None: print(f"decode: {why}"); return 1
    try: t = tarfile.open(fileobj=io.BytesIO(data)); names = t.getnames()
    except Exception as e: print(f"decode: archive unreadable: {e}"); return 1
    os.makedirs(outdir, exist_ok=True); t.extractall(outdir); open(os.path.join(outdir, "probe.tgz"), "wb").write(data)
    print(f"decode: {why}; {len(names)} entries extracted into {outdir}"); return 0

if __name__ == "__main__": sys.exit(main(sys.argv[1], sys.argv[2]))
