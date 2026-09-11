#!/bin/bash
# Bound-platform-statement probe for Google (protocol 3): the chip's report vouches that the guest held
# Google's own statements about the VM when it asked. Three SEV-SNP reports with one public nonce N:
#   r0    REPORT_DATA = N
#   r-ek  REPORT_DATA = SHA-512( N || SHA-256(vTPM RSA EK certificate, DER) )   the certificate carries the zone
#   r-jwt REPORT_DATA = SHA-512( N || SHA-256(Compute Engine identity token) )   the token carries the zone
# plus the hypervisor's certificate table. What Azure's paravisor does natively (REPORT_DATA = SHA-256 of
# its runtime JSON), done by hand here, as on AWS with the instance identity document.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1"; }
CLOUD=google; IID=$(md instance/name); ZONE=$(md instance/zone | awk -F/ '{print $NF}')
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "captured=$STAMP"; echo "probe=bind"; } > metadata.txt
uname -a > kernel.txt
md "instance/service-accounts/default/identity?audience=rats-probe&format=full" > gce-identity-token.jwt
export DEBIAN_FRONTEND=noninteractive; apt-get update -qq > apt.log 2>&1; apt-get install -y -qq tpm2-tools > /dev/null 2>> apt.log
tpm2_nvread -C o 0x01c00002 -o ek-rsa.der > ek.log 2>&1 || echo "no RSA EK cert at 0x01c00002" >> ek.log
tpm2_nvread -C o 0x01c0000a -o ek-ecc.der >> ek.log 2>&1 || echo "no ECC EK cert at 0x01c0000a" >> ek.log
openssl x509 -inform DER -in ek-rsa.der -noout -subject -issuer > ek-summary.txt 2>&1 || true
SENTENCE="rats geographic-results: bound platform statement probe, google instance $IID in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
python3 - <<'PY'
import ctypes, fcntl, os, struct, binascii, json, hashlib, uuid
N = binascii.unhexlify(open("nonce.hex").read().strip())
class Req(ctypes.Structure):    _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]
class Resp(ctypes.Structure):   _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure):  _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
class ExtReq(ctypes.Structure): _fields_ = [("data", Req), ("certs_address", ctypes.c_uint64), ("certs_len", ctypes.c_uint32)]
def report(user_data, name, ext=False):
    resp = Resp(); err = None
    if ext:
        certs = (ctypes.c_ubyte * 16384)(); req = ExtReq(); ctypes.memmove(req.data.user_data, user_data, 64); req.data.vmpl = 0; req.data.flags = 0; req.certs_address = ctypes.addressof(certs); req.certs_len = 16384; code = 0xC0205302
    else:
        req = Req(); ctypes.memmove(req.user_data, user_data, 64); req.vmpl = 0; req.flags = 0; code = 0xC0205300
    io = Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0); fd = os.open("/dev/sev-guest", os.O_RDWR)
    try: fcntl.ioctl(fd, code, io)
    except OSError as e: err = f"errno {e.errno} {e.strerror}"
    os.close(fd); rep = bytes(resp.report[:1184]); ok = err is None and resp.report_size == 1184
    r = {"name": name, "ok": ok, "fw_status": resp.status, "ioctl_error": err}
    if ok:
        open(f"report-{name}.bin", "wb").write(rep); flags = struct.unpack_from("<I", rep, 0x48)[0]
        r.update({"signing_key_bits": (flags >> 2) & 7, "chip_id": rep[0x1A0:0x1E0].hex()[:16], "report_id": rep[0x140:0x160].hex()[:16], "report_data": rep[0x50:0x90].hex()})
    if ext and err is None:
        GUIDS = {"63da758d-e664-4564-adc5-f4b93be8accd": "VCEK", "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK", "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK", "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK"}
        buf = bytes(certs); i = 0; r["table"] = []
        while i + 24 <= len(buf):
            g = buf[i:i + 16]; off, ln = struct.unpack_from("<II", buf, i + 16)
            if g == bytes(16): break
            nm = GUIDS.get(str(uuid.UUID(bytes_le=g)), GUIDS.get(str(uuid.UUID(bytes=g)), str(uuid.UUID(bytes=g)))); open(f"cert-{nm}.bin", "wb").write(buf[off:off + ln]); r["table"].append(nm); i += 24
    return r
ek = open("ek-rsa.der", "rb").read() if os.path.exists("ek-rsa.der") else b""; jwt = open("gce-identity-token.jwt", "rb").read()
res = {"r0": report(N, "r0", ext=True)}
if ek:
    rd = hashlib.sha512(N + hashlib.sha256(ek).digest()).digest(); res["r-ek"] = report(rd, "r-ek"); res["r-ek"]["bound_to"] = "SHA-512(N || SHA-256(ek-rsa.der))"; res["r-ek"]["binding_ok"] = res["r-ek"].get("report_data") == rd.hex(); res["r-ek"]["ek_sha256"] = hashlib.sha256(ek).hexdigest()
rd = hashlib.sha512(N + hashlib.sha256(jwt).digest()).digest(); res["r-jwt"] = report(rd, "r-jwt"); res["r-jwt"]["bound_to"] = "SHA-512(N || SHA-256(gce-identity-token.jwt))"; res["r-jwt"]["binding_ok"] = res["r-jwt"].get("report_data") == rd.hex(); res["r-jwt"]["jwt_sha256"] = hashlib.sha256(jwt).hexdigest()
res["r0"]["report_data_is_nonce"] = res["r0"].get("report_data") == N.hex()
json.dump(res, open("bind-results.json", "w"), indent=1)
PY
for f in cert-*.bin; do [ -f "$f" ] && { echo "== $f"; openssl x509 -inform PEM -in "$f" -noout -subject -issuer 2>/dev/null || openssl x509 -inform DER -in "$f" -noout -subject -issuer 2>/dev/null; }; done > certs-summary.txt 2>&1
sha256sum report-*.bin ek-rsa.der ek-ecc.der gce-identity-token.jwt nonce.hex cert-*.bin > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true; sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
