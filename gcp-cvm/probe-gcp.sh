#!/bin/bash
# Google Cloud Confidential VM probe (AMD SEV-SNP or Intel TDX). Runs as the GCE startup-script
# on Ubuntu 24.04 as root. Captures, with a public nonce:
#   - the raw hardware report: SEV-SNP ATTESTATION_REPORT through the SNP_GET_REPORT ioctl on
#     /dev/sev-guest (no third-party code), and through configfs-tsm where the kernel offers it;
#     TDX quote through configfs-tsm (/sys/kernel/config/tsm/report);
#   - the vTPM endorsement-key certificates from NV (Google-issued; they carry a GCE extension);
#   - the Google attestation token from the Confidential Computing attestation service (gotpm);
#   - the GCE service-account identity token (Google-signed, carries zone) for comparison;
#   - kernel, dmesg, devices, instance metadata.
# Everything is packed and written base64 to the serial console between markers.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
MD="http://metadata.google.internal/computeMetadata/v1"; md() { curl -s -H "Metadata-Flavor: Google" "$MD/$1"; }
NAME=$(md instance/name); ZONE=$(md instance/zone | awk -F/ '{print $NF}'); IID=$(md instance/id)
MT=$(md instance/machine-type | awk -F/ '{print $NF}'); PROJ=$(md project/project-id)
{ echo "instance-name=$NAME"; echo "instance-id=$IID"; echo "zone=$ZONE"; echo "machine-type=$MT"; echo "project=$PROJ"; echo "captured=$STAMP"; } > metadata.txt
md "instance/service-accounts/default/identity?audience=rats-probe&format=full" > gce-identity-token.jwt

uname -a > kernel.txt; cat /etc/os-release >> kernel.txt
dmesg | grep -i -E "sev|snp|tdx|memory encryption|tsm|tpm" > dmesg-cc.txt || true
ls -l /dev/sev-guest /dev/tdx_guest /dev/tpm0 /dev/tpmrm0 > devices.txt 2>&1 || true
grep -o -w -E "sev|sev_es|sev_snp|tdx_guest" /proc/cpuinfo | sort | uniq -c > cpuinfo-cc-flags.txt || true

SENTENCE="rats geographic-results: Google Cloud Confidential VM probe answering Sardar and Mandyam, 10 Sep 2026; instance $NAME ($IID) in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
python3 -c "import binascii;open('request-file.bin','wb').write(binascii.unhexlify(open('nonce.hex').read().strip()))"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > apt.log 2>&1; apt-get install -y -qq tpm2-tools openssl curl git ca-certificates >> apt.log 2>&1

TEE=none
if [ -e /dev/sev-guest ]; then
  TEE=snp
  python3 - > snp-ioctl.log 2>&1 <<'PY'
import ctypes, fcntl, os
class Req(ctypes.Structure):   _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 28)]
class Resp(ctypes.Structure):  _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure): _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
nonce = open("request-file.bin", "rb").read(); req = Req(); ctypes.memmove(req.user_data, nonce, 64); req.vmpl = 0
resp = Resp(); io = Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0)
fd = os.open("/dev/sev-guest", os.O_RDWR); fcntl.ioctl(fd, 0xC0205300, io); os.close(fd)   # SNP_GET_REPORT = _IOWR('S', 0, 32-byte struct)
rep = bytes(resp.report[:1184]); open("report.bin", "wb").write(rep); open("report.hex", "w").write(rep.hex() + "\n")
print("status", resp.status, "report_size", resp.report_size, "exitinfo2", hex(io.exitinfo2))
PY
fi
# configfs-tsm: SEV-SNP (provider sev_guest) or TDX (provider tdx_guest); kernel 6.7+
modprobe tsm_report 2>/dev/null || true; mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config 2>/dev/null || true
if [ -d /sys/kernel/config/tsm/report ]; then
  R=/sys/kernel/config/tsm/report/probe; mkdir -p "$R"
  cat request-file.bin > "$R/inblob" && cat "$R/provider" > tsm-provider.txt && cat "$R/outblob" > tsm-outblob.bin && cat "$R/generation" > tsm-generation.txt 2>/dev/null
  python3 -c "open('tsm-outblob.hex','w').write(open('tsm-outblob.bin','rb').read().hex()+'\n')"
  grep -q tdx tsm-provider.txt 2>/dev/null && { TEE=tdx; cp tsm-outblob.bin quote.bin; cp tsm-outblob.hex quote.hex; }
fi
echo "tee=$TEE" >> metadata.txt

# vTPM endorsement-key certificates (Google-issued for Shielded/Confidential VMs)
tpm2_nvread -C o 0x01c00002 -o ek-rsa.der > ek.log 2>&1 || echo "no RSA EK cert at 0x01c00002" >> ek.log
tpm2_nvread -C o 0x01c0000a -o ek-ecc.der >> ek.log 2>&1 || echo "no ECC EK cert at 0x01c0000a" >> ek.log
for f in ek-rsa.der ek-ecc.der; do [ -s "$f" ] && { echo "== $f"; openssl x509 -inform DER -in "$f" -noout -subject -issuer -serial -dates; openssl x509 -inform DER -in "$f" -noout -text | grep -A4 -E "Authority Information|Subject Alternative|1\.3\.6\.1\.4\.1\.11129"; }; done > ek-summary.txt 2>&1
tpm2_getcap properties-fixed > tpm-properties.txt 2>&1 || true

# Google attestation token (Confidential Computing attestation service) via go-tpm-tools' gotpm
( curl -sL https://go.dev/dl/go1.25.1.linux-amd64.tar.gz -o /tmp/go.tgz && tar -C /usr/local -xzf /tmp/go.tgz ) > go-install.log 2>&1
export PATH=/usr/local/go/bin:/root/go/bin:$PATH HOME=/root GOFLAGS=-buildvcs=false GOTOOLCHAIN=auto
# `go install ...@latest` refuses this module (replace directives), so clone and build in-tree
git clone -q --depth 1 https://github.com/google/go-tpm-tools /root/go-tpm-tools > gotpm-build.log 2>&1
( cd /root/go-tpm-tools && git rev-parse HEAD > "$OUT/gotpm-commit.txt" && go build -o /usr/local/bin/gotpm ./cmd/gotpm ) >> gotpm-build.log 2>&1
gotpm --help > gotpm-help.txt 2>&1 || true; gotpm token --help >> gotpm-help.txt 2>&1 || true
gotpm token --output gcp-attestation-token.jwt > gotpm-token.log 2>&1 || gotpm token --audience https://rats-probe --output gcp-attestation-token.jwt >> gotpm-token.log 2>&1 || echo "gotpm token failed" >> gotpm-token.log
gotpm attest --nonce "$(head -c 32 nonce.hex)" --output gotpm-attestation.bin > gotpm-attest.log 2>&1 || true

sha256sum report.bin quote.bin tsm-outblob.bin request-file.bin ek-rsa.der ek-ecc.der gcp-attestation-token.jwt gce-identity-token.jwt > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64")
{ echo "===PROBE-BEGIN=== $STAMP $NAME $ZONE $TEE size=$SZ"; cat "$STAMP.b64"; echo; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
echo "PROBE DONE $STAMP $NAME $ZONE $TEE size=$SZ" > /dev/ttyS0 2>/dev/null; echo "PROBE DONE $STAMP $NAME $ZONE $TEE size=$SZ"
