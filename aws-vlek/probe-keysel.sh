#!/bin/bash
# AWS EC2 SEV-SNP key-selection probe. Answers one question with data: can a guest obtain reports
# signed by BOTH the VLEK and the VCEK on the same machine? The SNP firmware ABI (MSG_REPORT_REQ,
# FLAGS bits 1:0 = KEY_SEL: 0 = VLEK if present else VCEK, 1 = VCEK only, 2 = VLEK only) exposes the
# choice; the Linux sev-guest ioctl passes the 96-byte request through, so KEY_SEL is set in the
# bytes right after VMPL. Three requests are made with the same public nonce, and for each the
# firmware status, the SIGNING_KEY bits of the returned report, CHIP_ID, and the key that verifies
# the signature are recorded. Runs as EC2 user-data on Amazon Linux 2023 (kernel 6.1).
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/$1"; }
IID=$(imds meta-data/instance-id); AZ=$(imds meta-data/placement/availability-zone); ITYPE=$(imds meta-data/instance-type)
{ echo "instance-id=$IID"; echo "az=$AZ"; echo "type=$ITYPE"; echo "captured=$STAMP"; echo "probe=keysel"; } > metadata.txt
uname -a > kernel.txt; dmesg | grep -i -E "sev|snp" > dmesg-sev.txt || true
SENTENCE="rats geographic-results: KEY_SEL probe answering Muhammad Usama Sardar, 11 Sep 2026 10:31Z (can a guest get VCEK and VLEK reports on one machine?); instance $IID in $AZ; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
python3 - <<'PY'
import ctypes, fcntl, os, struct, binascii, json
nonce = binascii.unhexlify(open("nonce.hex").read().strip())
class Req(ctypes.Structure):   _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]
class Resp(ctypes.Structure):  _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure): _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
results = []
for key_sel, label in ((0, "default"), (1, "vcek"), (2, "vlek")):
    req = Req(); ctypes.memmove(req.user_data, nonce, 64); req.vmpl = 0; req.flags = key_sel
    resp = Resp(); io = Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0)
    fd = os.open("/dev/sev-guest", os.O_RDWR); err = None
    try: fcntl.ioctl(fd, 0xC0205300, io)
    except OSError as e: err = f"{e.errno} {e.strerror}"
    os.close(fd)
    rep = bytes(resp.report[:1184]); ok = err is None and resp.report_size == 1184 and struct.unpack_from("<I", rep, 0)[0] in (2, 3, 4, 5)
    r = {"key_sel": key_sel, "label": label, "ioctl_error": err, "exitinfo2": hex(io.exitinfo2), "fw_status": resp.status, "report_size": resp.report_size, "report_ok": ok}
    if ok:
        flags = struct.unpack_from("<I", rep, 0x48)[0]
        r.update({"signing_key_bits": (flags >> 2) & 7, "signing_key": {0: "VCEK", 1: "VLEK", 7: "none"}.get((flags >> 2) & 7), "mask_chip_key": (flags >> 1) & 1,
                  "chip_id_zero": rep[0x1A0:0x1E0] == bytes(64), "chip_id_prefix": rep[0x1A0:0x1E0].hex()[:16], "report_data_is_nonce": rep[0x50:0x90] == nonce})
        open(f"report-keysel{key_sel}.bin", "wb").write(rep); open(f"report-keysel{key_sel}.hex", "w").write(rep.hex() + "\n")
    results.append(r); print(json.dumps(r))
json.dump(results, open("keysel-results.json", "w"), indent=1)
PY
# certificates offered by the host (extended report) and the KDS chains, for offline verification
export DEBIAN_FRONTEND=noninteractive; dnf install -y -q git cargo rust openssl perl > dnf.log 2>&1 || true
git clone -q https://github.com/virtee/snpguest.git /root/snpguest 2>> build.log; ( cd /root/snpguest && cargo build -r >> "$OUT/build.log" 2>&1 )
SNP=/root/snpguest/target/release/snpguest
if [ ! -x "$SNP" ]; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >> build.log 2>&1; export PATH="/root/.cargo/bin:$PATH"; ( cd /root/snpguest && cargo build -r >> "$OUT/build.log" 2>&1 ); fi
mkdir -p certs; $SNP certificates PEM ./certs > snpguest-certs.log 2>&1 || true; ls -l certs >> snpguest-certs.log
for f in certs/*.pem; do echo "== $f"; openssl x509 -in "$f" -noout -subject -issuer 2>/dev/null; done > certs-summary.txt 2>&1
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o kds-vlek-cert_chain.pem 2>> kds.log || true
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o kds-vcek-cert_chain.pem 2>> kds.log || true
sha256sum report-keysel*.bin nonce.hex certs/*.pem kds-*.pem > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" --exclude='build.log' --exclude='dnf.log' "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64")
{ echo "===PROBE-BEGIN=== $STAMP $IID $AZ size=$SZ"; cat "$STAMP.b64"; echo; echo "===PROBE-END==="; } > /dev/console 2>/dev/null || true
echo "PROBE DONE $STAMP $IID $AZ size=$SZ"
