#!/bin/bash
# Container-Optimized OS variant of the Google probe, for the Google Cloud Attestation token:
# the attestation verifier wants a measured-boot event log it recognises (it rejected the Ubuntu
# image with "no GRUB measurements found"), and COS is the image Google's own tooling targets.
# COS has no package manager, so gotpm is built and run inside a golang container with the
# TPM, the TEE device and configfs passed through. Runs as the GCE startup-script.
set -u
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/var/lib/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
exec > >(tee -a "$OUT/probe.log") 2>&1
MD="http://metadata.google.internal/computeMetadata/v1"; md() { curl -s -H "Metadata-Flavor: Google" "$MD/$1"; }
NAME=$(md instance/name); ZONE=$(md instance/zone | awk -F/ '{print $NF}'); IID=$(md instance/id); MT=$(md instance/machine-type | awk -F/ '{print $NF}'); PROJ=$(md project/project-id)
{ echo "instance-name=$NAME"; echo "instance-id=$IID"; echo "zone=$ZONE"; echo "machine-type=$MT"; echo "project=$PROJ"; echo "captured=$STAMP"; echo "image=cos"; } > metadata.txt
md "instance/service-accounts/default/identity?audience=rats-probe&format=full" > gce-identity-token.jwt
uname -a > kernel.txt; cat /etc/os-release >> kernel.txt
dmesg | grep -i -E "sev|snp|tdx|memory encryption|tsm" > dmesg-cc.txt || true
ls -l /dev/sev-guest /dev/tdx_guest /dev/tpm0 /dev/tpmrm0 > devices.txt 2>&1 || true
SENTENCE="rats geographic-results: Google Cloud Confidential VM probe (COS) answering Sardar and Mandyam, 10 Sep 2026; instance $NAME ($IID) in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
# raw report through configfs-tsm (no python on COS): inblob takes the 64 nonce bytes
TEE=none; mount -t configfs none /sys/kernel/config 2>/dev/null || true
if [ -d /sys/kernel/config/tsm/report ]; then
  R=/sys/kernel/config/tsm/report/probe; mkdir -p "$R"
  head -c 128 nonce.hex | xxd -r -p > request-file.bin 2>/dev/null || printf '%s' "$(head -c 128 nonce.hex)" | sed 's/\(..\)/\\x\1/g' | xargs -0 printf > request-file.bin
  cat request-file.bin > "$R/inblob" && cat "$R/provider" > tsm-provider.txt && cat "$R/outblob" > tsm-outblob.bin
  grep -q tdx tsm-provider.txt && TEE=tdx || TEE=snp
fi
echo "tee=$TEE" >> metadata.txt
DEV=(); [ -e /dev/sev-guest ] && DEV+=(--device /dev/sev-guest); [ -e /dev/tdx_guest ] && DEV+=(--device /dev/tdx_guest); [ -e /dev/tpmrm0 ] && DEV+=(--device /dev/tpmrm0); [ -e /dev/tpm0 ] && DEV+=(--device /dev/tpm0)
# --privileged: gotpm reads the TCG event log from securityfs and talks to the TPM and TEE devices; the default container profile denies that
docker run --rm --privileged ${DEV[@]+"${DEV[@]}"} -e GOTOOLCHAIN=auto -v "$OUT:/out" -v /sys:/sys:ro -v /sys/kernel/security:/sys/kernel/security:ro -v /sys/kernel/config:/sys/kernel/config golang:1.26 sh -c '
  set -e; git clone -q --depth 1 https://github.com/google/go-tpm-tools /src && cd /src && git rev-parse HEAD > /out/gotpm-commit.txt
  CGO_ENABLED=0 go build -o /tmp/gotpm ./cmd/gotpm && /tmp/gotpm --version > /out/gotpm-version.txt
  /tmp/gotpm token --output /out/gcp-attestation-token.jwt > /out/gotpm-token.log 2>&1 || /tmp/gotpm token --algo ecc --output /out/gcp-attestation-token.jwt >> /out/gotpm-token.log 2>&1 || echo "gotpm token failed" >> /out/gotpm-token.log
  /tmp/gotpm attest --nonce "$(head -c 32 /out/nonce.hex)" --output /out/gotpm-attestation.bin > /out/gotpm-attest.log 2>&1 || true
' > docker.log 2>&1
sha256sum tsm-outblob.bin request-file.bin gcp-attestation-token.jwt gce-identity-token.jwt gotpm-attestation.bin > sha256sums.txt 2>/dev/null
cd /var/lib/probe && tar czf "$STAMP.tgz" --exclude='*.bin.large' "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64")
{ echo "===PROBE-BEGIN=== $STAMP $NAME $ZONE $TEE size=$SZ"; cat "$STAMP.b64"; echo; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
echo "PROBE DONE $STAMP $NAME $ZONE $TEE size=$SZ" > /dev/ttyS0 2>/dev/null; echo "PROBE DONE $STAMP $NAME $ZONE $TEE size=$SZ"
