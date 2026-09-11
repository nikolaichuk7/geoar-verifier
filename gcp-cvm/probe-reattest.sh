#!/bin/bash
# Re-attestation probe (protocol 2, "does the workload still sit on the same chip?"). Runs at every
# boot as the startup script. Ten SEV-SNP reports twenty seconds apart, each with a fresh nonce
# (SHA-512 of a public sentence naming the boot and the sample), recording REPORT_ID, CHIP_ID,
# TCB and MEASUREMENT per sample; the operator then stops and starts the VM so that the second
# boot's archive shows whether the VM came back on the same chip. python3 + curl only.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=google; IID=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name); ZONE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')
GID=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id)
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "captured=$STAMP"; echo "probe=reattest"; echo "gce-instance-id=$GID"; echo "boot-id=$(cat /proc/sys/kernel/random/boot_id)"; } > metadata.txt
uname -a > kernel.txt; dmesg | grep -i -E "sev|snp" > dmesg-sev.txt || true
python3 - "$IID" "$ZONE" "$STAMP" <<'PY'
import ctypes, fcntl, os, struct, json, hashlib, time, sys
iid, zone, stamp = sys.argv[1:4]
class Req(ctypes.Structure):   _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]
class Resp(ctypes.Structure):  _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]
class Ioctl(ctypes.Structure): _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64), ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]
samples = []
for i in range(10):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()); up = float(open("/proc/uptime").read().split()[0])
    sentence = f"rats geographic-results: re-attestation probe, google instance {iid} in {zone}; boot {stamp}; sample {i} at {now}"
    N = hashlib.sha512(sentence.encode()).digest()
    req = Req(); ctypes.memmove(req.user_data, N, 64); req.vmpl = 0; req.flags = 0; resp = Resp(); io = Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0); err = None
    fd = os.open("/dev/sev-guest", os.O_RDWR)
    try: fcntl.ioctl(fd, 0xC0205300, io)
    except OSError as e: err = f"errno {e.errno}"
    os.close(fd); rep = bytes(resp.report[:1184]); ok = err is None and resp.report_size == 1184
    s = {"sample": i, "time": now, "uptime_s": up, "sentence": sentence, "ok": ok, "fw_status": resp.status, "ioctl_error": err}
    if ok:
        open(f"report-{i:02d}.bin", "wb").write(rep); tcb = struct.unpack_from("<Q", rep, 0x180)[0]
        s.update({"report_id": rep[0x140:0x160].hex(), "chip_id": rep[0x1A0:0x1E0].hex(), "measurement": rep[0x90:0xC0].hex(), "reported_tcb": hex(tcb), "signing_key_bits": (struct.unpack_from("<I", rep, 0x48)[0] >> 2) & 7, "report_data_is_nonce": rep[0x50:0x90] == N})
    samples.append(s); print(json.dumps({k: s[k] for k in ("sample", "time", "ok") if k in s}))
    if i < 9: time.sleep(20)
json.dump(samples, open("reattest-samples.json", "w"), indent=1)
PY
sha256sum report-*.bin reattest-samples.json metadata.txt > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true; sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
