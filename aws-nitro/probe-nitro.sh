#!/bin/bash
# AWS Nitro Enclaves probe. Runs once at first boot (user-data, root) on an enclave-enabled instance
# (Amazon Linux 2023). Builds a minimal enclave (python + cbor2 + cryptography) whose only job is to
# ask the Nitro Security Module for attestation documents and hand them to the parent over vsock:
#   doc-nonce      nonce = SHA-512 of the public sentence (received from the parent over vsock)
#   doc-bound      nonce + public_key = SPKI of an Ed25519 key generated inside the enclave + user_data;
#                  the key also signs the nonce (channel-binding demo, as in probe-dual.sh)
#   doc-nonce-2    the same nonce, a few seconds later
# The NSM ioctl is issued directly (no library): _IOWR(0x0A, 0, {iovec request, iovec response}).
# A second, debug-mode run captures the enclave console for diagnostics only (debug mode zeroes PCRs).
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=aws; TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"); imds() { curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/$1"; }
IID=$(imds meta-data/instance-id); ZONE=$(imds meta-data/placement/availability-zone); ITYPE=$(imds meta-data/instance-type)
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "instance-type=$ITYPE"; echo "captured=$STAMP"; echo "probe=nitro"; } > metadata.txt
uname -a > kernel.txt
dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker > dnf.log 2>&1
nitro-cli --version > nitro-cli-version.txt 2>&1
# cloud-init runs user-data in a non-login shell, so the package's profile script is not sourced (build-enclave then fails with E51)
[ -f /etc/profile.d/nitro-cli-env.sh ] && . /etc/profile.d/nitro-cli-env.sh; export NITRO_CLI_BLOBS=${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs} NITRO_CLI_ARTIFACTS=${NITRO_CLI_ARTIFACTS:-/var/lib/nitro_enclaves}; mkdir -p "$NITRO_CLI_ARTIFACTS"; env | grep NITRO_CLI > nitro-env.txt
printf -- '---\nmemory_mib: 1024\ncpu_count: 2\n' > /etc/nitro_enclaves/allocator.yaml
systemctl enable --now nitro-enclaves-allocator.service >> dnf.log 2>&1; systemctl enable --now docker >> dnf.log 2>&1
SENTENCE="rats geographic-results: Nitro Enclaves probe, aws instance $IID in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
mkdir -p enclave
cat > enclave/app.py <<'PY'
import ctypes, fcntl, os, socket, struct, time, hashlib, sys, cbor2
log = lambda *a: print("[app]", *a, file=sys.stderr, flush=True)
log("start")
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
class Iovec(ctypes.Structure): _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class NsmMessage(ctypes.Structure): _fields_ = [("request", Iovec), ("response", Iovec)]
NSM_IOCTL = 0xC0200A00  # _IOWR(0x0A, 0, sizeof(NsmMessage) = 32)
def nsm(req):
    rb = ctypes.create_string_buffer(cbor2.dumps(req)); resp = ctypes.create_string_buffer(16384)
    m = NsmMessage(Iovec(ctypes.cast(rb, ctypes.c_void_p), len(rb.raw) - 1), Iovec(ctypes.cast(resp, ctypes.c_void_p), 16384))
    fd = os.open("/dev/nsm", os.O_RDWR); fcntl.ioctl(fd, NSM_IOCTL, m); os.close(fd)
    return cbor2.loads(resp.raw[:m.response.len])
def attest(nonce, user_data=None, public_key=None):
    r = nsm({"Attestation": {"user_data": user_data, "nonce": nonce, "public_key": public_key}})
    return r["Attestation"]["document"] if "Attestation" in r else cbor2.dumps({"error": repr(r)})
log("nsm device:", os.path.exists("/dev/nsm")); s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); log("connecting"); s.connect((3, 5000)); log("connected")          # parent = CID 3
def send(name, data):
    n = name.encode(); s.sendall(struct.pack(">B", len(n)) + n + struct.pack(">I", len(data)) + data)
def recvall(k):
    b = b""
    while len(b) < k: b += s.recv(k - len(b))
    return b
N = recvall(struct.unpack(">I", recvall(4))[0])                                          # the nonce, 64 bytes
send("describe.cbor", cbor2.dumps(nsm({"DescribeNSM": None})))
send("doc-nonce.cbor", attest(N))
key = ed25519.Ed25519PrivateKey.generate(); spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
send("doc-bound.cbor", attest(N, user_data=b"geoar-verifier nitro probe; user_data = this string", public_key=spki)); send("eph-pub.der", spki); send("eph-sig.bin", key.sign(N))
time.sleep(3); send("doc-nonce-2.cbor", attest(N))
send("done", b""); s.close(); log("done")
PY
cat > enclave/Dockerfile <<'DF'
FROM python:3.12-slim
RUN pip install --no-cache-dir cbor2==5.6.5 cryptography==44.0.2
COPY app.py /app.py
CMD ["/usr/local/bin/python3", "/app.py"]
DF
docker build -q -t nsm-probe enclave   # CMD uses the absolute interpreter path: the enclave init has no PATH (attempt 4: "execvpe: python3: No such file or directory") > docker-build.log 2>&1
nitro-cli build-enclave --docker-uri nsm-probe:latest --output-file nsm-probe.eif > build-enclave.json 2> build-enclave.err
cat > listener.py <<'PY'
import socket, struct, json, sys
srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); srv.bind((socket.VMADDR_CID_ANY, 5000)); srv.listen(1); srv.settimeout(150)
N = bytes.fromhex(open("nonce.hex").read().strip()); got = []
try:
    c, _ = srv.accept(); c.settimeout(120); c.sendall(struct.pack(">I", len(N)) + N)
    def recvall(k):
        b = b""
        while len(b) < k: b += c.recv(k - len(b))
        return b
    while True:
        name = recvall(struct.unpack(">B", recvall(1))[0]).decode(); data = recvall(struct.unpack(">I", recvall(4))[0])
        if name == "done": break
        open(name, "wb").write(data); got.append([name, len(data)])
except Exception as e: got.append(f"error: {e!r}")
json.dump(got, open("listener-result.json", "w"))
PY
run_once() {  # $1 = directory for this run's files, $2... = extra run-enclave flags
  mkdir -p "$1"; cp nonce.hex listener.py "$1/"; ( cd "$1" && python3 listener.py > listener.log 2>&1 ) & LPID=$!; sleep 1
  timeout 150 nitro-cli run-enclave --eif-path nsm-probe.eif --cpu-count 2 --memory 1024 --enclave-cid 16 "${@:2}" > "$1/run-enclave.out" 2>&1
  wait $LPID; nitro-cli describe-enclaves > "$1/describe-enclaves.json" 2>&1; nitro-cli terminate-enclave --all > "$1/terminate.json" 2>&1
}
run_once debug --debug-mode --attach-console          # diagnostics only: PCR0-2 are zero in debug mode, so debug/doc-*.cbor are not evidence
run_once . && rm -f listener.py.bak
sha256sum doc-*.cbor describe.cbor eph-pub.der eph-sig.bin nonce.hex build-enclave.json listener-result.json > sha256sums.txt 2>/dev/null; rm -f debug/nonce.hex debug/listener.py
rm -rf enclave nsm-probe.eif
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true; sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > /dev/console 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
