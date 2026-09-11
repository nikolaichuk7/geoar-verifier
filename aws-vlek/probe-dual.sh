#!/bin/bash
# Dual-key SEV-SNP probe. Distro-agnostic (python3 + openssl + curl only; no Rust build).
# One guest, one public nonce, and the following requests through the SNP_GET_REPORT /
# SNP_GET_EXT_REPORT ioctls on /dev/sev-guest:
#   k0  KEY_SEL = 0   firmware default (VLEK if loaded, else VCEK)   REPORT_DATA = N
#   k1  KEY_SEL = 1   VCEK requested explicitly                       REPORT_DATA = N
#   k2  KEY_SEL = 2   VLEK requested explicitly                       REPORT_DATA = N
#   ch  chained pair: A = KEY_SEL 2 with REPORT_DATA = N, then B = KEY_SEL 1 with
#       REPORT_DATA = SHA-512(A), so that a VCEK-signed report vouches for the VLEK-signed one
#       (or the reverse if only one key exists: recorded either way)
#   cb  channel-binding demo: an ephemeral Ed25519 key is generated in the guest, the report's
#       REPORT_DATA = SHA-512(N || SubjectPublicKeyInfo), and the key signs N; a Verifier that
#       checks all three has a report bound to a key it can then use in a session
# The extended report is also requested so that the certificate table the hypervisor hands to
# the guest (VLEK / VCEK / ASK / ARK, whichever it offers) is captured without any tool.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
[ -f /etc/probe-env ] && . /etc/probe-env    # bare metal: CLOUD=baremetal IID=<guest name> ZONE=<site> written by the host's cloud-init seed
if [ "${CLOUD:-}" = baremetal ]; then
  :
elif curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id >/dev/null 2>&1; then
  CLOUD=google; IID=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name); ZONE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')
else
  CLOUD=aws; TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"); imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/$1"; }
  IID=$(imds meta-data/instance-id); ZONE=$(imds meta-data/placement/availability-zone); TEN=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/host-id 2>/dev/null); [ -n "$TEN" ] && echo "host-id=$TEN" > tenancy.txt
fi
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "captured=$STAMP"; echo "probe=dual"; cat tenancy.txt 2>/dev/null; } > metadata.txt
uname -a > kernel.txt; dmesg | grep -i -E "sev|snp" > dmesg-sev.txt || true
SENTENCE="rats geographic-results: dual-key probe answering Muhammad Usama Sardar, 11 Sep 2026 10:31Z; $CLOUD instance $IID in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
openssl genpkey -algorithm ed25519 -out eph-key.pem 2>/dev/null; openssl pkey -in eph-key.pem -pubout -outform DER -out eph-pub.der 2>/dev/null
python3 - <<'PY'
import ctypes, fcntl, os, struct, binascii, json, hashlib, subprocess
N = binascii.unhexlify(open("nonce.hex").read().strip())
class Req(ctypes.Structure):    _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]
class Resp(ctypes.Structure):   _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure):  _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
class ExtReq(ctypes.Structure): _fields_ = [("data", Req), ("certs_address", ctypes.c_uint64), ("certs_len", ctypes.c_uint32)]
SNP_GET_REPORT, SNP_GET_EXT_REPORT = 0xC0205300, 0xC0205302
def parse(rep):
    flags = struct.unpack_from("<I", rep, 0x48)[0]
    return {"version": struct.unpack_from("<I", rep, 0)[0], "signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7, (flags >> 2) & 7), "mask_chip_key": (flags >> 1) & 1,
            "chip_id_zero": rep[0x1A0:0x1E0] == bytes(64), "chip_id_prefix": rep[0x1A0:0x1E0].hex()[:16], "report_id": rep[0x140:0x160].hex()[:16], "measurement": rep[0x90:0xC0].hex()[:16], "report_data": rep[0x50:0x90].hex()}
def get_report(user_data, key_sel, name):
    req = Req(); ctypes.memmove(req.user_data, user_data, 64); req.vmpl = 0; req.flags = key_sel
    resp = Resp(); io = Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0); err = None
    fd = os.open("/dev/sev-guest", os.O_RDWR)
    try: fcntl.ioctl(fd, SNP_GET_REPORT, io)
    except OSError as e: err = f"errno {e.errno} {e.strerror}"
    os.close(fd)
    rep = bytes(resp.report[:1184]); ok = err is None and resp.report_size == 1184 and struct.unpack_from("<I", rep, 0)[0] in (2, 3, 4, 5)
    r = {"name": name, "key_sel": key_sel, "ioctl_error": err, "exitinfo2": hex(io.exitinfo2), "fw_status": resp.status, "ok": ok}
    if ok:
        r.update(parse(rep)); open(f"report-{name}.bin", "wb").write(rep); open(f"report-{name}.hex", "w").write(rep.hex() + "\n")
    return r, (rep if ok else None)
results = {}
for ks, name in ((0, "k0"), (1, "k1"), (2, "k2")):
    results[name], _ = get_report(N, ks, name)
# chained pair: A = VLEK (2) if it worked, else default; B = VCEK (1) with REPORT_DATA = SHA-512(A)
a_sel = 2 if results["k2"]["ok"] else 0
ra, rep_a = get_report(N, a_sel, "chA")
if rep_a is not None:
    rb, rep_b = get_report(hashlib.sha512(rep_a).digest(), 1, "chB")
    rb["report_data_is_sha512_of_chA"] = (rb.get("report_data") == hashlib.sha512(rep_a).hexdigest()) if rb["ok"] else None
    rb["same_report_id_as_chA"] = (rb.get("report_id") == ra.get("report_id")) if rb["ok"] else None
    results["chA"], results["chB"] = ra, rb
# channel binding: REPORT_DATA = SHA-512(N || SPKI); the ephemeral key signs N
spki = open("eph-pub.der", "rb").read(); rc, _ = get_report(hashlib.sha512(N + spki).digest(), 0, "cb")
if rc["ok"]:
    open("nonce.bin", "wb").write(N); subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", "eph-key.pem", "-rawin", "-in", "nonce.bin", "-out", "eph-sig.bin"], check=False)
    rc["report_data_is_sha512_nonce_spki"] = rc["report_data"] == hashlib.sha512(N + spki).hexdigest(); rc["spki_sha256"] = hashlib.sha256(spki).hexdigest()[:16]
results["cb"] = rc
# extended report: certificate table from the hypervisor
certs = (ctypes.c_ubyte * 16384)(); ereq = ExtReq(); ctypes.memmove(ereq.data.user_data, N, 64); ereq.data.vmpl = 0; ereq.data.flags = 0  # 0x4000 = SEV_FW_BLOB_MAX_SIZE, page-aligned, else the driver returns EINVAL
ereq.certs_address = ctypes.addressof(certs); ereq.certs_len = 16384; eresp = Resp(); eio = Ioctl(1, ctypes.addressof(ereq), ctypes.addressof(eresp), 0); err = None
fd = os.open("/dev/sev-guest", os.O_RDWR)
try: fcntl.ioctl(fd, SNP_GET_EXT_REPORT, eio)
except OSError as e: err = f"errno {e.errno} {e.strerror}"
os.close(fd)
GUIDS = {"63da758d-e664-4564-adc5-f4b93be8accd": "VCEK", "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK", "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK", "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK"}
table = []
if err is None:
    buf = bytes(certs); i = 0
    while i + 24 <= len(buf):
        g = buf[i:i + 16]; off, ln = struct.unpack_from("<II", buf, i + 16)
        if g == bytes(16): break
        import uuid; name = GUIDS.get(str(uuid.UUID(bytes=g)), str(uuid.UUID(bytes=g))); blob = buf[off:off + ln]
        open(f"cert-{name}.bin", "wb").write(blob); table.append({"guid": name, "offset": off, "length": ln, "pem": blob[:10] == b"-----BEGIN"}); i += 24
results["ext_report"] = {"ioctl_error": err, "exitinfo2": hex(eio.exitinfo2), "fw_status": eresp.status, "certs_len_returned": ereq.certs_len, "table": table}
json.dump(results, open("dual-results.json", "w"), indent=1)
PY
for f in cert-*.bin; do [ -f "$f" ] && { echo "== $f"; openssl x509 -inform PEM -in "$f" -noout -subject -issuer 2>/dev/null || openssl x509 -inform DER -in "$f" -noout -subject -issuer 2>/dev/null; }; done > certs-summary.txt 2>&1
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o kds-vlek-cert_chain.pem 2>/dev/null || true
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o kds-vcek-cert_chain.pem 2>/dev/null || true
sha256sum report-*.bin nonce.hex eph-pub.der eph-sig.bin cert-*.bin kds-*.pem > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
# Serial-console transport that survives interleaving: the base64 is cut into 76-char lines, each line carries
# its index, the block is written three times, and the collector reassembles by index and checks the SHA-256.
# (The 11 Sep runs lost their payloads to cloud-init / journald lines landing in the middle of one long line.)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true
DEV=/dev/ttyS0; [ "$CLOUD" = aws ] && DEV=/dev/console
sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > $DEV 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
