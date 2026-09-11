#!/usr/bin/env python3
"""Reassemble a probe archive from a serial-console capture and extract it.

Usage: decode_console.py <console.txt> <outdir>   ->  exit 0 only after a SHA-256-verified extraction.

The probe writes the base64 archive as 76-char lines "@@NNNN <b64>", three copies, between
"===PROBE-BEGIN=== <stamp> <id> <zone> <cloud> size=<n> sha256=<hex> lines=<k> copy=<c>" and
"===PROBE-END===". Console output from other writers (cloud-init, journald, the kernel) can land
inside or even in the middle of a line, so lines are taken from any copy, by index, only when they
have the expected length, and the whole base64 must hash to the value the probe printed.
The legacy single-line format (no "@@" lines) is still accepted when its length matches size=.
A console may carry several archives from one VM (one per boot, distinct <stamp>): each stamp is
reassembled on its own and extracted; the exit status is 0 when every stamp seen was extracted."""
import sys, re, base64, io, tarfile, os, hashlib

def decode_one(text, head):
    """Reassemble the archive whose BEGIN header is `head` (a match object); returns (bytes|None, why)."""
    stamp = head.group(1).split()[0]; size = int(head.group(2)); sha = head.group(3); nlines = int(head.group(4)) if head.group(4) else None
    if sha:
        cand = {}
        # only the blocks of this stamp: the text between each BEGIN of this stamp and the next END
        for h in re.finditer(r"===PROBE-BEGIN=== " + re.escape(stamp) + r" [^\n]*\n", text):
            end = text.find("===PROBE-END===", h.end()); block = text[h.end():end if end > 0 else None]
            for m in re.finditer(r"@@(\d{4}) ([A-Za-z0-9+/=]+)", block):
                i = int(m.group(1)); want = 76 if i < nlines - 1 else size - 76 * (nlines - 1)
                if len(m.group(2)) == want: cand.setdefault(i, m.group(2))
        missing = [i for i in range(nlines) if i not in cand]
        if missing: return None, f"{stamp}: {len(missing)} of {nlines} lines not yet intact (e.g. {missing[:5]})"
        b64 = "".join(cand[i] for i in range(nlines))
        if len(b64) != size: return None, f"{stamp}: assembled {len(b64)} chars, expected {size}"
        if hashlib.sha256(b64.encode()).hexdigest() != sha: return None, f"{stamp}: sha256 mismatch after reassembly"
        return base64.b64decode(b64), f"{stamp}: sha256 verified over {nlines} lines"
    end = text.find("===PROBE-END===", head.end()); body = re.sub(r"[^A-Za-z0-9+/=]", "", text[head.end():end if end > 0 else None])
    if len(body) == size: return base64.b64decode(body), f"{stamp}: legacy single-line payload, length matched"
    return None, f"{stamp}: legacy payload length mismatch"

def decode(text):
    """Returns {stamp: (bytes|None, why)} for every distinct stamp announced on the console."""
    text = re.sub(r"\[\d{4}-\d{2}-\d{2}T[\d:.]+\]", "", text)          # EC2 serial-console timestamps
    heads = list(re.finditer(r"===PROBE-BEGIN=== ([^\n]*?)size=(\d+)(?: sha256=([0-9a-f]{64}) lines=(\d+) copy=(\d+))?", text))
    out = {}
    for h in heads:
        stamp = h.group(1).split()[0]
        if stamp in out and out[stamp][0] is not None: continue
        out[stamp] = decode_one(text, h)
    return out

def main(console, outdir):
    text = open(console, errors="replace").read(); results = decode(text)
    if not results: print("decode: no BEGIN marker"); return 1
    rc = 0
    for stamp, (data, why) in results.items():
        if data is None: print(f"decode: {why}"); rc = 1; continue
        try: t = tarfile.open(fileobj=io.BytesIO(data)); names = t.getnames()
        except Exception as e: print(f"decode: {stamp}: archive unreadable: {e}"); rc = 1; continue
        os.makedirs(outdir, exist_ok=True); t.extractall(outdir); open(os.path.join(outdir, f"probe-{stamp}.tgz"), "wb").write(data)
        print(f"decode: {why}; {len(names)} entries extracted into {outdir}")
    return rc

if __name__ == "__main__": sys.exit(main(sys.argv[1], sys.argv[2]))
