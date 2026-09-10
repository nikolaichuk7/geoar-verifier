#!/usr/bin/env python3
"""Minimal CBOR Diagnostic Notation (RFC 8949 section 8) printer with embedded-CBOR (<<...>>) for COSE_Sign1 payloads.
Usage: python3 cbor_diag.py file.cbor [file2 ...]   -> writes file.diag next to each input and prints it."""
import cbor2, sys, pathlib, datetime
from collections.abc import Mapping
def diag(o, ind=0, embed_payload=False):
    pad = "  " * ind
    if isinstance(o, cbor2.CBORTag):
        if o.tag == 18 and isinstance(o.value, (list, tuple)) and len(o.value) == 4:
            prot, unp, payload, sig = o.value
            body = [f"{pad}  / protected / << {diag(cbor2.loads(prot))} >>", f"{pad}  / unprotected / {diag(unp)}",
                    f"{pad}  / payload / << {diag(cbor2.loads(payload), ind + 1)} >>", f"{pad}  / signature / h'{sig.hex()}'"]
            return "18([\n" + ",\n".join(body) + f"\n{pad}])"
        if o.tag == 1: return f"1({int(o.value.timestamp()) if hasattr(o.value, 'timestamp') else o.value})"
        return f"{o.tag}({diag(o.value, ind)})"
    if isinstance(o, datetime.datetime): return f"1({int(o.timestamp())})"
    if isinstance(o, bool): return "true" if o else "false"
    if o is None: return "null"
    if isinstance(o, int): return str(o)
    if isinstance(o, float): return repr(o)
    if isinstance(o, bytes): return f"h'{o.hex()}'"
    if isinstance(o, str): return '"' + o.replace('\\', '\\\\').replace('"', '\\"') + '"'
    if isinstance(o, (list, tuple)): return "[" + ", ".join(diag(x, ind) for x in o) + "]"
    if isinstance(o, Mapping):
        items = [f"{pad}  {diag(k)}: {diag(v, ind + 1)}" for k, v in o.items()]
        return "{\n" + ",\n".join(items) + f"\n{pad}}}"
    return repr(o)
if __name__ == "__main__":
    for f in sys.argv[1:]:
        p = pathlib.Path(f); text = diag(cbor2.loads(p.read_bytes())) + "\n"
        out = p.with_suffix(".diag"); out.write_text(text); print(f"== {out.name}\n{text}")
