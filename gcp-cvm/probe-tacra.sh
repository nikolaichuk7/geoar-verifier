#!/bin/bash
# TACRA (draft-novak-rats-tacra-00) enrollment worked example on AMD SEV-SNP.
# Models the Credential Acquisition Interface (Section 4.4): generate a credential signing key (CSK)
# and a CSR (PKCS#10, proof of possession of CSKpri), take the Credential Authority's present-nonce
# freshness handle (Section 2.1), and bind CSR+nonce into Evidence:
#   REPORT_DATA = SHA-512(nonce || CSR_DER)
# then obtain a VCEK-signed SEV-SNP report. This answers the draft's open "CSR-to-Evidence binding"
# TODO with a concrete, verifiable construction. The Credential Authority (tacra_verify.py)
# recomputes the binding, verifies the report and its VCEK chain to ARK-Milan, and verifies the
# CSR's own signature, then may issue for CSKpub. The credential private key never leaves the guest.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=google; IID=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name); ZONE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')
NONCE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/ca-nonce)
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "ca_nonce=$NONCE"; echo "captured=$STAMP"; echo "probe=tacra"; } > metadata.txt
printf '%s' "$NONCE" > ca-nonce.hex
uname -a > kernel.txt; dmesg 2>/dev/null | grep -i -E "sev|snp" > dmesg-sev.txt || true

# ensure /dev/sev-guest
if [ ! -e /dev/sev-guest ]; then modprobe sev-guest 2>/dev/null || true; fi
if [ ! -e /dev/sev-guest ]; then export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq linux-modules-extra-$(uname -r) >/dev/null 2>&1; modprobe sev-guest 2>/dev/null || true; fi
n=0; while [ ! -e /dev/sev-guest ] && [ $n -lt 60 ]; do sleep 1; n=$((n+1)); done; ls -l /dev/sev-guest > devices.txt 2>&1 || true

# CAI: credential signing key (CSK) + CSR (proof of possession of CSKpri); ship only public parts
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out csk.pem 2>/dev/null
openssl req -new -key csk.pem -subj "/CN=workload.tacra.example" -outform DER -out csr.der 2>/dev/null
openssl pkey -in csk.pem -pubout -outform DER -out csk-pub.der 2>/dev/null
rm -f csk.pem   # the credential private key never leaves the guest

# TACRA enrollment binding into Evidence: REPORT_DATA = SHA-512(nonce || CSR_DER)  (SHA-512 = 64 bytes)
{ printf '%s' "$NONCE" | xxd -r -p; cat csr.der; } | sha512sum | cut -d' ' -f1 | xxd -r -p > reportdata.bin
echo "reportdata size = $(stat -c%s reportdata.bin) (want 64)"

python3 - <<'PYIOCTL'
import ctypes, fcntl, os, struct, json, uuid
RD = open("reportdata.bin","rb").read(); assert len(RD)==64
class Req(ctypes.Structure):    _fields_ = [("user_data", ctypes.c_ubyte*64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte*24)]
class Resp(ctypes.Structure):   _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte*24), ("report", ctypes.c_ubyte*4000)]
class Ioctl(ctypes.Structure):  _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
class ExtReq(ctypes.Structure): _fields_ = [("data", Req), ("certs_address", ctypes.c_uint64), ("certs_len", ctypes.c_uint32)]
SNP_GET_REPORT, SNP_GET_EXT_REPORT = 0xC0205300, 0xC0205302
def parse(rep):
    flags = struct.unpack_from("<I", rep, 0x48)[0]
    return {"version": struct.unpack_from("<I", rep, 0)[0], "signing_key": {0:"VCEK",1:"VLEK",7:"none"}.get((flags>>2)&7,(flags>>2)&7),
            "mask_chip_key": (flags>>1)&1, "chip_id_zero": rep[0x1A0:0x1E0]==bytes(64), "chip_id_prefix": rep[0x1A0:0x1E0].hex()[:16],
            "report_id": rep[0x140:0x160].hex()[:16], "measurement": rep[0x90:0xC0].hex()[:16], "report_data": rep[0x50:0x90].hex()}
results={}
req=Req(); ctypes.memmove(req.user_data, RD, 64); req.vmpl=0; req.flags=1
resp=Resp(); io=Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0); err=None
fd=os.open("/dev/sev-guest", os.O_RDWR)
try: fcntl.ioctl(fd, SNP_GET_REPORT, io)
except OSError as e: err=f"errno {e.errno} {e.strerror}"
os.close(fd)
rep=bytes(resp.report[:1184]); ok = err is None and resp.report_size==1184 and struct.unpack_from("<I",rep,0)[0] in (2,3,4,5)
r={"name":"tacra","key_sel":1,"ioctl_error":err,"exitinfo2":hex(io.exitinfo2),"fw_status":resp.status,"ok":ok}
if ok: r.update(parse(rep)); open("report-tacra.bin","wb").write(rep)
results["tacra"]=r
certs=(ctypes.c_ubyte*16384)(); ereq=ExtReq(); ctypes.memmove(ereq.data.user_data, RD, 64); ereq.data.vmpl=0; ereq.data.flags=1
ereq.certs_address=ctypes.addressof(certs); ereq.certs_len=16384; eresp=Resp(); eio=Ioctl(1, ctypes.addressof(ereq), ctypes.addressof(eresp), 0); err=None
fd=os.open("/dev/sev-guest", os.O_RDWR)
try: fcntl.ioctl(fd, SNP_GET_EXT_REPORT, eio)
except OSError as e: err=f"errno {e.errno} {e.strerror}"
os.close(fd)
GUIDS={"63da758d-e664-4564-adc5-f4b93be8accd":"VCEK","a8074bc2-a25a-483e-aae6-39c045a0b8a1":"VLEK","4ab7b379-bbac-4fe4-a02f-05aef327c782":"ASK","c0b406a4-a803-4952-9743-3fb6014cd0ae":"ARK"}
table=[]
if err is None:
    buf=bytes(certs); i=0
    while i+24<=len(buf):
        g=buf[i:i+16]; off,ln=struct.unpack_from("<II",buf,i+16)
        if g==bytes(16): break
        name=GUIDS.get(str(uuid.UUID(bytes=g)),str(uuid.UUID(bytes=g))); blob=buf[off:off+ln]
        open(f"cert-{name}.bin","wb").write(blob); table.append({"guid":name,"offset":off,"length":ln,"pem":blob[:10]==b"-----BEGIN"}); i+=24
results["ext_report"]={"ioctl_error":err,"table":table}
json.dump(results, open("ioctl-results.json","w"), indent=1)
print("REPORT ok=", results["tacra"]["ok"], "chip=", results["tacra"].get("chip_id_prefix"), "signing=", results["tacra"].get("signing_key"))
PYIOCTL

for f in cert-*.bin; do [ -f "$f" ] && { echo "== $f"; openssl x509 -inform DER -in "$f" -noout -subject -issuer 2>/dev/null || openssl x509 -inform PEM -in "$f" -noout -subject -issuer 2>/dev/null; }; done > certs-summary.txt 2>&1
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o kds-vcek-cert_chain.pem 2>/dev/null || true
sha256sum report-*.bin reportdata.bin csr.der csk-pub.der ca-nonce.hex cert-*.bin kds-*.pem metadata.txt > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true
DEV=/dev/ttyS0
sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > $DEV 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
