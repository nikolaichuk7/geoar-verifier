#!/usr/bin/env python3
"""End-to-end chain for the TRIP-style evidence-class example. SYNTHETIC trajectory, labelled as such; real cryptography.

  Attester (device)      -> 64 H3 res-10 cells, 15 min apart, each Ed25519-signed          = Evidence
  Verifier A (geographic)-> verifies signatures, resolves whole cells to one country, emits R1 in a COSE_Sign1 EAR:
                            jurisdiction-country, claim-uuid U1, basis = evidence (0) [+ proposed: provence, observed-from/until]
  Verifier B (workload)  -> consumes A's EAR as an Attestation Result, emits R2 in its own COSE_Sign1 EAR:
                            basis = attestation-result (2), claim-uuid U2, basis-ref U1 [proposed label]
  Relying Party          -> verifies signatures against its trust anchors, walks basis-ref, applies an appraisal policy for results.
  The same RP policy is run over the two NL results of the 26-artifact run (SEV-SNP, basis 2 without a reference; Azure, basis 1).

Usage: python3 trip_chain.py <ne_10m_admin_0_countries.geojson> <two-claims-check.cddl>
"""
import cbor2, h3, json, hashlib, uuid, random, math, subprocess, datetime, sys, pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from shapely.geometry import shape, Polygon
from shapely.prepared import prep

HERE = pathlib.Path(__file__).parent; OUT = HERE / "vectors-trip"; OUT.mkdir(exist_ok=True)
NE, STRICT = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]); EXT = OUT / "ext-check.cddl"
UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/mcr/geographicresult")
# labels: 0..12 on main; 13 claim-uuid and 14 basis from PR #6; 15..18 are PROPOSALS encoded here so that they can be argued with in bytes
L_COUNTRY, L_UUID, L_BASIS, L_PROV, L_BASIS_REF, L_OBS_FROM, L_OBS_UNTIL = 0, 13, 14, 15, 16, 17, 18
EVIDENCE, ENDORSEMENT, ATTESTATION_RESULT = 0, 1, 2
EAT_PROFILE, EAT_IAT, EAT_SUBMODS, EAR_VERIFIER, EAR_STATUS, TIER_AFFIRM, GEO_LABEL = 265, 6, 266, 1004, 1000, 2, -70100
EAR_PROFILE_TAG = "tag:ietf.org,2026:rats/ear#04"
RES, N, STEP_MIN = 10, 64, 15
EU = set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split())

def key_from(seed): return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
def raw(pub): return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def cose_sign1(payload, key, kid):
    protected = cbor2.dumps({1: -8})                                   # alg EdDSA
    sig = key.sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {4: kid}, payload, sig]))
def cose_open(msg, anchors):
    """returns (kid, payload) if the signature verifies against a trusted key, else raises"""
    t = cbor2.loads(msg); assert t.tag == 18; protected, unprot, payload, sig = t.value; kid = unprot[4]
    if kid not in anchors: raise PermissionError(f"signer {kid!r} not in trust anchors")
    anchors[kid].verify(sig, cbor2.dumps(["Signature1", protected, b"", payload])); return kid, payload
def ear(verifier_id, geo_map, iat, submod="trip-device"):
    return {EAT_PROFILE: EAR_PROFILE_TAG, EAT_IAT: iat, EAR_VERIFIER: {0: verifier_id, 1: "2026-09-10"}, EAT_SUBMODS: {submod: {EAR_STATUS: TIER_AFFIRM, GEO_LABEL: geo_map}}}
def geo_of(payload):
    p = cbor2.loads(payload); return next(sm[GEO_LABEL] for sm in p[EAT_SUBMODS].values() if GEO_LABEL in sm), p[EAR_VERIFIER][0]
def cddl_ok(cddl, path): return subprocess.run(["cddl", str(cddl), "validate", str(path)], capture_output=True).returncode == 0

# ---- 1. Attester. Either the producer-supplied set (argv[3]: cells + collection times, unsigned) or the built-in synthetic walk.
dev = key_from(b"trip-synthetic-device-2026-09-10"); dev_pub = raw(dev.public_key())   # deterministic device key so vectors reproduce
def msg(c): return cbor2.dumps([c["seq"], c["ts"], c["cell"]])
SUPPLIED = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else None
if SUPPLIED:
    src = json.loads(SUPPLIED.read_text()); cells, times = src["h3_cells"], src["collection_times_unix_s"]
    assert len(cells) == len(times) == N and all(h3.get_resolution(c) == RES for c in cells), "supplied set is not 64 cells at resolution 10"
    crumbs = [{"seq": i, "ts": int(times[i]), "cell": cells[i]} for i in range(N)]
    kind = f"Producer-supplied set ({SUPPLIED.name}, labelled synthetic by its author), cells and collection times verbatim; the set carries no signatures, so each breadcrumb is signed here with the example's device key"
else:
    rng = random.Random(20260910); lat, lng = 52.3731, 4.8922
    t0 = datetime.datetime(2026, 9, 9, 6, 0, tzinfo=datetime.timezone.utc); crumbs = []
    for i in range(N):
        ts = int((t0 + datetime.timedelta(minutes=STEP_MIN * i)).timestamp()); d = rng.uniform(40, 120); ang = rng.uniform(0, 2 * math.pi)
        lat += d * math.cos(ang) / 111_320; lng += d * math.sin(ang) / (111_320 * math.cos(math.radians(lat)))
        crumbs.append({"seq": i, "ts": ts, "cell": h3.latlng_to_cell(lat, lng, RES)})
    kind = "SYNTHETIC trajectory evidence, TRIP-style; not produced by TRIP"
for c in crumbs: c["sig"] = dev.sign(msg(c)).hex()
evidence = {"kind": kind, "h3_resolution": RES, "device_pub_ed25519": dev_pub.hex(), "crumbs": crumbs}

# ---- 2. Verifier A: signatures, window, whole-cell containment against Natural Earth 10m admin-0
feats = json.load(open(NE))["features"]
polys = [((f["properties"].get("ISO_A2_EH") or f["properties"]["ISO_A2"]), f["properties"]["ADMIN"], prep(shape(f["geometry"]))) for f in feats]
def country_of_cell(cell):
    poly = Polygon([(lo, la) for la, lo in h3.cell_to_boundary(cell)])
    return next(((iso, name) for iso, name, g in polys if g.contains(poly)), (None, None))  # the WHOLE cell must lie inside one country
def verifier_A(ev):
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ev["device_pub_ed25519"])); cs = ev["crumbs"]
    for c in cs:
        try: pk.verify(bytes.fromhex(c["sig"]), msg(c))
        except InvalidSignature: return None, f"signature failed on seq {c['seq']}"
    if len(cs) != N: return None, "window is not 64 cells"
    if any(b["ts"] - a["ts"] < STEP_MIN * 60 for a, b in zip(cs, cs[1:])): return None, "spacing under 15 minutes"
    found = {}
    for c in cs: found.setdefault(country_of_cell(c["cell"])[0], []).append(c["cell"])
    if len(found) != 1 or None in found: return None, f"cells resolve to {sorted(str(k) for k in found)}; no single jurisdiction"
    cc = next(iter(found)); digest = hashlib.sha256(json.dumps(cs, sort_keys=True).encode()).hexdigest()
    u1 = uuid.uuid5(UUID_NS, ("trip-supplied:" if SUPPLIED else "trip-synthetic:") + digest)
    core = {L_COUNTRY: cc, L_UUID: u1.bytes, L_BASIS: EVIDENCE}
    ext = dict(core); ext.update({L_PROV: "I-D.trip", L_OBS_FROM: cbor2.CBORTag(1, cs[0]["ts"]), L_OBS_UNTIL: cbor2.CBORTag(1, cs[-1]["ts"])})
    return {"core": core, "ext": ext, "uuid": u1, "country": cc, "name": next(n for i, n, g in polys if i == cc)}, f"64/64 signatures verified; 64/64 whole cells inside {cc}"
A, B, X = key_from(b"verifier-A-geographic"), key_from(b"verifier-B-workload"), key_from(b"nobody-trusts-this-key")
r1, noteA = verifier_A(evidence); assert r1, noteA
iat = crumbs[-1]["ts"] + 60
ear_A = cose_sign1(cbor2.dumps(ear("geoar-verifier-A", r1["ext"], iat)), A, b"A")

# ---- 3. Verifier B: takes A's EAR as an Attestation Result, emits its own with basis = attestation-result and basis-ref = U1
def verifier_B(ear_from_A, with_ref=True):
    kid, payload = cose_open(ear_from_A, {b"A": A.public_key()})       # B trusts A for geographic results
    g, _ = geo_of(payload); u2 = uuid.uuid5(UUID_NS, "hop2:" + g[L_UUID].hex())
    m = {L_COUNTRY: g[L_COUNTRY], L_UUID: u2.bytes, L_BASIS: ATTESTATION_RESULT}
    if with_ref: m[L_BASIS_REF] = g[L_UUID]
    for k in (L_OBS_FROM, L_OBS_UNTIL):                                   # cbor2 decodes tag 1 into datetime; re-encode as tag 1 epoch seconds
        if k in g: m[k] = cbor2.CBORTag(1, int(g[k].timestamp())) if hasattr(g[k], "timestamp") else g[k]
    return m, cose_sign1(cbor2.dumps(ear("workload-verifier-B", m, iat + 5, submod="workload")), B, b"B")
r2, ear_B = verifier_B(ear_A); r2n, ear_B_noref = verifier_B(ear_A, with_ref=False)
ear_rogue = cose_sign1(cbor2.dumps(ear("geoar-verifier-A", r1["ext"], iat)), X, b"A")   # forged: claims to be A, signed by an untrusted key

# ---- 4. the two NL results from the 26-artifact run, payload bytes unchanged, re-signed by A for the demo
run = json.load(open(HERE / "geoar-run-27-two-claims.json")); run = run if isinstance(run, list) else run.get("results", run)
nl = {r["family"]: bytes.fromhex(r["ear_hex"]) for r in run if r.get("country") == "NL"}
ear_snp = cose_sign1(nl["SEV-SNP"], A, b"A"); ear_azure = cose_sign1(nl["Azure"], A, b"A")

# ---- 5. Relying Party: appraisal policy for attestation results, RFC 9334 Section 7 vocabulary
anchors = {b"A": A.public_key(), b"B": B.public_key()}
store = {r1["uuid"].bytes: ear_A, uuid.UUID(bytes=r2[L_UUID]).bytes: ear_B}
def rp(msg_bytes, policy, depth=0):
    try: kid, payload = cose_open(msg_bytes, anchors)
    except Exception as e: return "REJECT", f"signature: {type(e).__name__}: {e}".rstrip(": ")
    g, vid = geo_of(payload); cc = g.get(L_COUNTRY); basis = g.get(L_BASIS)
    if cc not in EU: return "REJECT", f"{cc} outside the EU"
    if policy == "lenient": return "ACCEPT", f"{cc} from trusted {vid}, basis {basis} not examined"
    if basis in (EVIDENCE, ENDORSEMENT): return "ACCEPT", f"{cc}, basis {basis} ({'evidence' if basis == 0 else 'endorsement'}) from {vid}"
    if basis == ATTESTATION_RESULT:
        ref = g.get(L_BASIS_REF)
        if not ref: return "REJECT", f"{cc}, basis attestation-result from {vid} with no basis-ref: rests on a result that cannot be audited"
        if ref not in store: return "REJECT", f"basis-ref {uuid.UUID(bytes=ref)} not resolvable"
        if depth > 4: return "REJECT", "chain too deep"
        v, why = rp(store[ref], policy, depth + 1)
        return ("ACCEPT" if v == "ACCEPT" else "REJECT"), f"{cc} via basis-ref {str(uuid.UUID(bytes=ref))[:8]}: upstream {v} ({why})"
    return "REJECT", "no basis"
cases = [("R1 EAR from A (evidence)", ear_A), ("R2 EAR from B (attestation-result, basis-ref U1)", ear_B), ("R2 without basis-ref", ear_B_noref),
         ("forged EAR, kid A, untrusted key", ear_rogue), ("26-run SEV-SNP NL (basis 2, no ref)", ear_snp), ("26-run Azure NL (basis 1)", ear_azure)]
table = [{"case": n, "strict": rp(m, "strict"), "lenient": rp(m, "lenient")} for n, m in cases]

# ---- 6. bytes, files, CDDL
ext_cddl = STRICT.read_text().replace("  ? grc.basis-label => grc.basis-class\n",
    "  ? grc.basis-label => grc.basis-class\n  ? grc.provence-label => tstr .size (1..12)\n  ? grc.basis-ref-label => corim.uuid-type\n  ? grc.observed-from-label => time\n  ? grc.observed-until-label => time\n") \
    + "\n; PROPOSED labels, not in PR #6: provence from PR #4 moved off 13 (taken by claim-uuid), a reference to the result this one rests on, and an observation window for longitudinal evidence\n" \
      "grc.provence-label = eat.JC<\"grc.provence\", 15>\ngrc.basis-ref-label = eat.JC<\"grc.basis-ref\", 16>\ngrc.observed-from-label = eat.JC<\"grc.observed-from\", 17>\ngrc.observed-until-label = eat.JC<\"grc.observed-until\", 18>\n; time is the CDDL prelude type #6.1(number)\n"
EXT.write_text(ext_cddl)
files = {"r1-core.cbor": cbor2.dumps(r1["core"]), "r1-ext.cbor": cbor2.dumps(r1["ext"]), "r2.cbor": cbor2.dumps(r2), "r2-noref.cbor": cbor2.dumps(r2n),
         "ear-A.cose": ear_A, "ear-B.cose": ear_B, "ear-B-noref.cose": ear_B_noref, "ear-rogue.cose": ear_rogue, "ear-snp-nl.cose": ear_snp, "ear-azure-nl.cose": ear_azure}
for n, b in files.items(): (OUT / n).write_bytes(b)
(OUT / ("evidence-supplied-signed.json" if SUPPLIED else "evidence-synthetic.json")).write_text(json.dumps(evidence, indent=1))
prev = (OUT / "result-evidence.cbor").read_bytes() if (OUT / "result-evidence.cbor").exists() else None
report = {
 "evidence_source": evidence["kind"], "verifier_A": noteA, "boundaries": "Natural Earth 10m admin-0 countries (nvkelso/natural-earth-vector, fetched 2026-09-10); rule: the whole H3 cell polygon must lie inside one country polygon",
 "window": {"cells": N, "distinct_cells": len({c["cell"] for c in crumbs}), "interval_min": STEP_MIN, "span_hours": (crumbs[-1]["ts"] - crumbs[0]["ts"]) / 3600, "h3_res10_edge_m": round(h3.average_hexagon_edge_length(RES, unit="m"), 1)},
 "bytes": {n: len(b) for n, b in files.items()},
 "r1_core_hex": files["r1-core.cbor"].hex(), "r1_core_identical_to_yesterday_vector": (prev == files["r1-core.cbor"]) if prev else None,
 "r2_hex": files["r2.cbor"].hex(), "U1": str(r1["uuid"]), "U2": str(uuid.UUID(bytes=r2[L_UUID])),
 "cddl": {"r1-core vs PR#6": cddl_ok(STRICT, OUT / "r1-core.cbor"), "r1-ext vs PR#6 (expected false: proposed labels)": cddl_ok(STRICT, OUT / "r1-ext.cbor"),
          "r1-ext vs ext": cddl_ok(EXT, OUT / "r1-ext.cbor"), "r2 vs ext": cddl_ok(EXT, OUT / "r2.cbor"), "r2 vs PR#6 (expected false)": cddl_ok(STRICT, OUT / "r2.cbor")},
 "relying_party": table,
}
(OUT / "chain-report.json").write_text(json.dumps(report, indent=1)); print(json.dumps(report, indent=1))
