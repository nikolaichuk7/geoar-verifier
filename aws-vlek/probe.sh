#!/bin/bash
# AWS EC2 SEV-SNP probe: capture one attestation report signed with the VLEK (shared tenancy),
# the host-supplied certificate table, the AMD KDS VLEK chain, and enough guest-side metadata
# to reproduce every statement made about it. Runs as EC2 user-data on Amazon Linux 2023.
#
# Everything the probe learns is written to /root/probe/<stamp>/ and, encoded once as base64,
# to the serial console between the markers ===PROBE-BEGIN=== / ===PROBE-END===, so that the
# operator can retrieve it with `aws ec2 get-console-output --latest` and no inbound port or
# IAM role is needed. If PROBE_POST_URL is set, the same archive is also POSTed there.
#
# REPORT_DATA (the 64-byte nonce inside the signed report) is not random: it is
# SHA-512 over a public sentence that names the mailing-list message being answered and the
# instance that answers it, so that anyone can recompute it and see the report was made for
# this thread and not replayed from an earlier capture.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/$1"; }
IID=$(imds meta-data/instance-id); AZ=$(imds meta-data/placement/availability-zone)
REGION=$(imds meta-data/placement/region); ITYPE=$(imds meta-data/instance-type); AMI=$(imds meta-data/ami-id)
imds dynamic/instance-identity/document > instance-identity.json
imds dynamic/instance-identity/pkcs7 > instance-identity.pkcs7
{ echo "instance-id=$IID"; echo "az=$AZ"; echo "region=$REGION"; echo "type=$ITYPE"; echo "ami=$AMI"; echo "captured=$STAMP"; } > metadata.txt

# Guest-side evidence that SEV-SNP is active, independent of the report itself.
uname -a > kernel.txt; cat /etc/os-release >> kernel.txt
dmesg | grep -i -E "sev|snp|memory encryption" > dmesg-sev.txt || true
ls -l /dev/sev-guest > dev-sev-guest.txt 2>&1 || true
grep -o -w -E "sev|sev_es|sev_snp" /proc/cpuinfo | sort | uniq -c > cpuinfo-sev-flags.txt || true

# Nonce: SHA-512 of a public sentence. Recompute with: printf '%s' "<sentence>" | sha512sum
SENTENCE="rats geographic-results: reply to Muhammad Usama Sardar and Giridhar Mandyam, 10 Sep 2026 22:00Z/22:42Z; AWS EC2 SEV-SNP VLEK probe; instance $IID in $AZ; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt
printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
python3 - <<'PY'
import binascii
h=open("nonce.hex").read().strip(); open("request-file.bin","wb").write(binascii.unhexlify(h))
PY

# Tooling: snpguest, the utility AWS documents for exactly this procedure.
dnf install -y -q git cargo rust openssl perl > dnf.log 2>&1 || echo "dnf failed" >> dnf.log
git clone -q https://github.com/virtee/snpguest.git /root/snpguest 2>> build.log
( cd /root/snpguest && git rev-parse HEAD > "$OUT/snpguest-commit.txt" && cargo build -r >> "$OUT/build.log" 2>&1 )
SNP=/root/snpguest/target/release/snpguest
if [ ! -x "$SNP" ]; then   # distro toolchain too old for the crate graph: fall back to rustup stable
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >> "$OUT/build.log" 2>&1
  export PATH="/root/.cargo/bin:$PATH"; rustc --version >> "$OUT/build.log" 2>&1
  ( cd /root/snpguest && cargo build -r >> "$OUT/build.log" 2>&1 )
fi
$SNP --version > snpguest-version.txt 2>&1 || true

# 1. Report with our nonce (--random NOT used), plus the raw request file for reproduction.
$SNP report report.bin request-file.bin > snpguest-report.log 2>&1 || echo "report failed" >> snpguest-report.log
$SNP display report report.bin > report-display.txt 2>&1 || true
# 2. Certificates the hypervisor supplies with the extended report (VLEK leaf lives here).
mkdir -p certs; $SNP certificates PEM ./certs > snpguest-certs.log 2>&1 || echo "certificates failed" >> snpguest-certs.log
ls -l certs >> snpguest-certs.log; for f in certs/*.pem; do echo "== $f"; openssl x509 -in "$f" -noout -subject -issuer -serial -dates -ext subjectAltName 2>/dev/null; openssl x509 -in "$f" -noout -text 2>/dev/null | grep -A2 -E "1\.3\.6\.1\.4\.1\.3704" ; done > certs-summary.txt 2>&1
# 3. AMD KDS chain for VLEK (ASVK + ARK) and, for comparison, the VCEK chain (ASK + ARK).
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o kds-vlek-cert_chain.pem 2>> kds.log || echo "kds vlek chain failed" >> kds.log
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o kds-vcek-cert_chain.pem 2>> kds.log || echo "kds vcek chain failed" >> kds.log
[ -f certs/vlek.pem ] && openssl verify -CAfile kds-vlek-cert_chain.pem certs/vlek.pem > openssl-verify-vlek.txt 2>&1
# 4. snpguest's own verification, as documented by AWS.
$SNP verify certs ./certs > verify-certs.txt 2>&1 || true
$SNP verify attestation ./certs report.bin > verify-attestation.txt 2>&1 || true
# 5. Second report, seconds later, same nonce: shows which fields move between two requests.
sleep 2; $SNP report report-2.bin request-file.bin > /dev/null 2>&1 || true
sha256sum report.bin report-2.bin request-file.bin certs/*.pem kds-*.pem > sha256sums.txt 2>/dev/null

# Package and emit.
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"
SZ=$(stat -c%s "$STAMP.b64")
{ echo "===PROBE-BEGIN=== $STAMP $IID $AZ size=$SZ"; cat "$STAMP.b64"; echo; echo "===PROBE-END==="; } > /dev/console 2>/dev/null || true
{ echo "===PROBE-BEGIN=== $STAMP $IID $AZ size=$SZ"; cat "$STAMP.b64"; echo; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
if [ -n "${PROBE_POST_URL:-}" ]; then curl -s -X POST -H "Content-Type: text/plain" --data-binary "@$STAMP.b64" "$PROBE_POST_URL?id=$IID&az=$AZ&stamp=$STAMP" > /root/probe/post.log 2>&1; fi
echo "PROBE DONE $STAMP $IID $AZ size=$SZ"
