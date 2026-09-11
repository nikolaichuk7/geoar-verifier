#!/bin/bash
# NitroTPM probe: what does AWS's virtual TPM certify, and does anything in it name a place?
# Reads the EK certificates from the TPM NV indexes, the TPM's fixed properties, and takes a quote
# with the public nonce as qualifying data under a freshly created AK (no AK certificate exists on
# NitroTPM, so the quote documents the mechanism only). Amazon Linux 2023 with tpm2-tools.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=aws; TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"); imds() { curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/$1"; }
IID=$(imds meta-data/instance-id); ZONE=$(imds meta-data/placement/availability-zone); ITYPE=$(imds meta-data/instance-type)
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "instance-type=$ITYPE"; echo "captured=$STAMP"; echo "probe=nitrotpm"; } > metadata.txt
uname -a > kernel.txt; ls -l /dev/tpm0 /dev/tpmrm0 > devices.txt 2>&1; dmesg | grep -i tpm > dmesg-tpm.txt || true
dnf install -y -q tpm2-tools > dnf.log 2>&1
SENTENCE="rats geographic-results: NitroTPM probe, aws instance $IID in $ZONE; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex; printf '%s' "$SENTENCE" | sha256sum | cut -d' ' -f1 > nonce256.hex
tpm2_getcap properties-fixed > tpm-properties.txt 2>&1
tpm2_nvreadpublic > nv-indexes.txt 2>&1
tpm2_nvread -C o 0x01c00002 -o ek-rsa.der > ek.log 2>&1 || echo "no RSA EK cert at 0x01c00002" >> ek.log
tpm2_nvread -C o 0x01c0000a -o ek-ecc.der >> ek.log 2>&1 || echo "no ECC EK cert at 0x01c0000a" >> ek.log
for f in ek-rsa.der ek-ecc.der; do [ -s "$f" ] && { echo "== $f"; openssl x509 -inform DER -in "$f" -noout -subject -issuer -serial -dates 2>&1; openssl x509 -inform DER -in "$f" -noout -text 2>/dev/null | grep -A3 "Authority Information Access\|Subject Alternative Name"; }; done > ek-summary.txt 2>&1
tpm2_createek -c ek.ctx -G rsa -u ek.pub > ak.log 2>&1 && tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name >> ak.log 2>&1 \
  && tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7 -q "$(cat nonce256.hex)" -m quote.msg -s quote.sig -o quote.pcrs -g sha256 >> ak.log 2>&1 && tpm2_pcrread sha256 > pcrs.txt 2>&1
tpm2_readpublic -c ak.ctx -o ak-pub.pem -f pem >> ak.log 2>&1 || true
imds dynamic/instance-identity/document > identity-document.json
sha256sum ek-rsa.der ek-ecc.der quote.msg quote.sig quote.pcrs ak.pub nonce.hex > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64"); H=$(sha256sum "$STAMP.b64" | cut -d' ' -f1)
fold -w 76 "$STAMP.b64" | awk '{printf "@@%04d %s\n", NR-1, $0}' > "$STAMP.lines"; NL=$(wc -l < "$STAMP.lines")
dmesg -n 1 2>/dev/null || true; sleep 5
for COPY in 1 2 3; do
  { echo; echo "===PROBE-BEGIN=== $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL copy=$COPY"; cat "$STAMP.lines"; echo "===PROBE-END==="; } > /dev/console 2>/dev/null || true
  sleep 3
done
echo "PROBE DONE $STAMP $IID $ZONE $CLOUD size=$SZ sha256=$H lines=$NL"
