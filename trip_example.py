#!/usr/bin/env python3
"""Evidence-class worked example for draft-richardson-rats-geographic-results, TRIP-style, SYNTHETIC and labelled as such.

Evidence: 64 device-signed breadcrumbs, each an H3 resolution-10 cell plus a timestamp, 15 minutes apart, Ed25519-signed
(the shape Camilo Ayerbe described for TRIP on 2026-09-09). The device never signs a coordinate; only the quantised cell.

Geographic Verifier policy (this file):
  1. verify all 64 Ed25519 signatures against the device public key; refuse on any failure
  2. check the window: 64 samples, monotonic timestamps, spacing >= 15 minutes
  3. resolve each cell's centroid to a country by point-in-polygon against Natural Earth 50m admin-0 boundaries
  4. emit a geographic result only if every cell resolves to the same country; otherwise emit nothing
  5. encode jurisdiction-country with grc.basis = evidence (0) and grc.claim-uuid = uuid5(namespace, sha256(evidence set))
  6. validate the CBOR against the CDDL of PR #6 with the cddl gem

Usage: python3 trip_example.py <ne_50m_admin_0_countries.geojson> <check.cddl>
"""
import cbor2, h3, json, hashlib, uuid, random, math, subprocess, datetime, sys, pathlib, binascii
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from shapely.geometry import shape, Point
from shapely.prepared import prep

HERE = pathlib.Path(__file__).parent; OUT = HERE / "vectors-trip"; OUT.mkdir(exist_ok=True)
NE, CHECK = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/mcr/geographicresult")
L_COUNTRY, L_UUID, L_BASIS = 0, 13, 14
BASIS = {"evidence": 0, "endorsement": 1, "attestation-result": 2}
RES, N, STEP_MIN = 10, 64, 15

# ---- 1. synthetic trajectory (Amsterdam, walking-scale moves), quantised to H3 res 10 before anything is signed
rng = random.Random(20260910)
lat, lng = 52.3731, 4.8922
t0 = datetime.datetime(2026, 9, 9, 6, 0, tzinfo=datetime.timezone.utc)
crumbs = []
for i in range(N):
    ts = int((t0 + datetime.timedelta(minutes=STEP_MIN * i)).timestamp())
    d = rng.uniform(40, 120); ang = rng.uniform(0, 2 * math.pi)
    lat += d * math.cos(ang) / 111_320; lng += d * math.sin(ang) / (111_320 * math.cos(math.radians(lat)))
    crumbs.append({"seq": i, "ts": ts, "cell": h3.latlng_to_cell(lat, lng, RES)})

# ---- 2. the device signs each breadcrumb (Ed25519), coordinate never leaves the device
# deterministic device key so the vectors reproduce byte for byte
dev = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"trip-synthetic-device-2026-09-10").digest()); pub = dev.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def msg(c): return cbor2.dumps([c["seq"], c["ts"], c["cell"]])
for c in crumbs: c["sig"] = dev.sign(msg(c)).hex()
evidence = {"kind": "SYNTHETIC trajectory evidence, TRIP-style; not produced by TRIP", "h3_resolution": RES, "device_pub_ed25519": pub.hex(), "crumbs": crumbs}
(OUT / "evidence-synthetic.json").write_text(json.dumps(evidence, indent=1))

# ---- 3. the geographic Verifier
features = json.load(open(NE))["features"]
polys = [(f["properties"].get("ISO_A2_EH") or f["properties"]["ISO_A2"], f["properties"]["ADMIN"], prep(shape(f["geometry"]))) for f in features]
def country_of(cell):
    la, lo = h3.cell_to_latlng(cell); p = Point(lo, la)
    return next(((iso, name) for iso, name, g in polys if g.contains(p)), (None, None))

def verify_and_conclude(ev):
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ev["device_pub_ed25519"])); cs = ev["crumbs"]
    for c in cs:
        try: pk.verify(bytes.fromhex(c["sig"]), msg(c))
        except InvalidSignature: return None, f"signature failed on seq {c['seq']}"
    if len(cs) != N: return None, "window is not 64 cells"
    if any(b["ts"] - a["ts"] < STEP_MIN * 60 for a, b in zip(cs, cs[1:])): return None, "spacing under 15 minutes"
    found = {}
    for c in cs:
        iso, name = country_of(c["cell"]); found.setdefault(iso, []).append(c["cell"])
    if len(found) != 1 or None in found: return None, f"cells resolve to {list(found)}; no single jurisdiction"
    cc = next(iter(found)); digest = hashlib.sha256(json.dumps(ev["crumbs"], sort_keys=True).encode()).hexdigest()
    return {L_COUNTRY: cc, L_UUID: uuid.uuid5(UUID_NS, "trip-synthetic:" + digest).bytes, L_BASIS: BASIS["evidence"]}, f"64/64 signatures verified; 64/64 cells in {cc} ({polys and next(n for i, n, g in polys if i == cc)})"

result, note = verify_and_conclude(evidence)
report = {"note": note}
if result:
    cbor = cbor2.dumps(result); (OUT / "result-evidence.cbor").write_bytes(cbor)
    report.update({"bytes": len(cbor), "hex": cbor.hex(), "country": result[L_COUNTRY], "basis": result[L_BASIS], "claim_uuid": str(uuid.UUID(bytes=result[L_UUID]))})
    v = subprocess.run(["cddl", str(CHECK), "validate", str(OUT / "result-evidence.cbor")], capture_output=True, text=True)
    report["cddl_valid"] = (v.returncode == 0); report["cddl_output"] = (v.stdout + v.stderr).strip()[:300]

# ---- 4. negative controls
tampered = json.loads(json.dumps(evidence)); tampered["crumbs"][17]["cell"] = h3.latlng_to_cell(48.8566, 2.3522, RES)  # Paris cell under the Amsterdam signature
r2, note2 = verify_and_conclude(tampered); report["control_tampered_cell"] = {"result_emitted": r2 is not None, "note": note2}
bad = cbor2.dumps({L_COUNTRY: "NL", L_UUID: bytes(16), L_BASIS: 3}); (OUT / "bad-basis-3.cbor").write_bytes(bad)
v = subprocess.run(["cddl", str(CHECK), "validate", str(OUT / "bad-basis-3.cbor")], capture_output=True, text=True); report["control_basis_3_rejected"] = (v.returncode != 0)
# a window that spans two countries: the Amsterdam walk with its last 8 cells replaced by a walk in Antwerp (BE); policy says no result
rng2 = random.Random(1); lat, lng = 51.2194, 4.4025; crumbs2 = json.loads(json.dumps(crumbs))
for i in range(N - 8, N):
    d = rng2.uniform(40, 120); ang = rng2.uniform(0, 2 * math.pi)
    lat += d * math.cos(ang) / 111_320; lng += d * math.sin(ang) / (111_320 * math.cos(math.radians(lat)))
    crumbs2[i]["cell"] = h3.latlng_to_cell(lat, lng, RES); crumbs2[i]["sig"] = dev.sign(msg(crumbs2[i])).hex()
r3, note3 = verify_and_conclude({"device_pub_ed25519": pub.hex(), "crumbs": crumbs2}); report["control_two_countries"] = {"result_emitted": r3 is not None, "note": note3}
report["h3_res10_edge_m"] = round(h3.average_hexagon_edge_length(RES, unit="m"), 1)
report["window"] = {"cells": N, "interval_min": STEP_MIN, "span_hours": (crumbs[-1]["ts"] - crumbs[0]["ts"]) / 3600, "distinct_cells": len({c["cell"] for c in crumbs})}
(OUT / "report.json").write_text(json.dumps(report, indent=1)); print(json.dumps(report, indent=1))
