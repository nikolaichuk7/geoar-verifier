#!/bin/bash
# AWS-only probe: bind the AWS-signed instance identity document into an SEV-SNP report.
# REPORT_DATA = SHA-512( N || SHA-256(identity document) ), N = SHA-512(public sentence).
# The document (region, availabilityZone, instanceId) is signed by AWS (PKCS#7 and RSA-2048 detached
# signatures from IMDS); the report is signed by the VLEK whose certificate carries AMD's CSP_ID for the
# region. Two signers, one binding, no new field. Distro-agnostic (python3 + openssl + curl).
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=aws; TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"); imds() { curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/$1"; }
IID=$(imds meta-data/instance-id); ZONE=$(imds meta-data/placement/availability-zone)
imds dynamic/instance-identity/document > identity-document.json; imds dynamic/instance-identity/pkcs7 > identity-pkcs7.b64; imds dynamic/instance-identity/signature > identity-rsa2048.b64
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "captured=$STAMP"; echo "probe=idbind"; } > metadata.txt
uname -a > kernel.txt
SENTENCE="rats geographic-results: identity-document binding probe, $CLOUD instance $IID in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
python3 - <<'PY'
import ctypes, fcntl, os, struct, binascii, json, hashlib, uuid
N = binascii.unhexlify(open("nonce.hex").read().strip()); doc = open("identity-document.json", "rb").read()
RD = hashlib.sha512(N + hashlib.sha256(doc).digest()).digest()
class Req(ctypes.Structure):    _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]
class Resp(ctypes.Structure):   _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure):  _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
class ExtReq(ctypes.Structure): _fields_ = [("data", Req), ("certs_address", ctypes.c_uint64), ("certs_len", ctypes.c_uint32)]
certs = (ctypes.c_ubyte * 16384)(); ereq = ExtReq(); ctypes.memmove(ereq.data.user_data, RD, 64); ereq.data.vmpl = 0; ereq.data.flags = 0
ereq.certs_address = ctypes.addressof(certs); ereq.certs_len = 16384; resp = Resp(); io = Ioctl(1, ctypes.addressof(ereq), ctypes.addressof(resp), 0); err = None
fd = os.open("/dev/sev-guest", os.O_RDWR)
try: fcntl.ioctl(fd, 0xC0205302, io)
except OSError as e: err = f"errno {e.errno} {e.strerror}"
os.close(fd)
rep = bytes(resp.report[:1184]); ok = err is None and resp.report_size == 1184
r = {"ioctl_error": err, "exitinfo2": hex(io.exitinfo2), "fw_status": resp.status, "ok": ok, "table": []}
if ok:
    flags = struct.unpack_from("<I", rep, 0x48)[0]; open("report-idbind.bin", "wb").write(rep)
    r.update({"signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7), "chip_id_zero": rep[0x1A0:0x1E0] == bytes(64), "report_id": rep[0x140:0x160].hex()[:16],
              "report_data_is_sha512_nonce_docdigest": rep[0x50:0x90] == RD, "doc_sha256": hashlib.sha256(doc).hexdigest()})
    GUIDS = {"63da758d-e664-4564-adc5-f4b93be8accd": "VCEK", "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK", "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK", "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK"}
    buf = bytes(certs); i = 0
    while i + 24 <= len(buf):
        g = buf[i:i + 16]; off, ln = struct.unpack_from("<II", buf, i + 16)
        if g == bytes(16): break
        name = GUIDS.get(str(uuid.UUID(bytes_le=g)), GUIDS.get(str(uuid.UUID(bytes=g)), str(uuid.UUID(bytes=g)))); open(f"cert-{name}.bin", "wb").write(buf[off:off + ln]); r["table"].append(name); i += 24
json.dump(r, open("idbind-results.json", "w"), indent=1)
PY
for f in cert-*.bin; do [ -f "$f" ] && { echo "== $f"; openssl x509 -in "$f" -noout -subject -issuer 2>/dev/null; }; done > certs-summary.txt 2>&1
sha256sum report-idbind.bin identity-document.json identity-pkcs7.b64 identity-rsa2048.b64 nonce.hex cert-*.bin > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true; sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > /dev/console 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
