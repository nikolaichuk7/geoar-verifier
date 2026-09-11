#!/bin/bash
# Azure Confidential VM probe (DCasv5 = AMD SEV-SNP, DCesv5 = Intel TDX). Runs once as root via
# cloud-init custom-data on the Ubuntu CVM image. Captures:
#   - the HCL report from the vTPM NV index 0x01400001 (hardware report + runtime data JSON);
#   - the AMD VCEK / certificate chain from Azure THIM (SEV-SNP), or the TD quote from the IMDS
#     /acc/tdquote endpoint (TDX);
#   - a vTPM quote with the HCL attestation key over our public nonce (freshness), plus the
#     EK / AK public parts and the EK certificate;
#   - a Microsoft Azure Attestation token (best effort, REST call to the shared regional provider);
#   - instance metadata (region, VM id, size), kernel, dmesg.
# Written base64 to the serial console between markers for `az vm boot-diagnostics get-boot-log`.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
IMDS="http://169.254.169.254/metadata"; imds() { curl -s -H "Metadata:true" "$IMDS/$1"; }
imds "instance?api-version=2021-02-01" > instance-metadata.json
REGION=$(python3 -c "import json;print(json.load(open('instance-metadata.json'))['compute']['location'])"); NAME=$(python3 -c "import json;print(json.load(open('instance-metadata.json'))['compute']['name'])")
VMID=$(python3 -c "import json;print(json.load(open('instance-metadata.json'))['compute']['vmId'])"); SIZE=$(python3 -c "import json;print(json.load(open('instance-metadata.json'))['compute']['vmSize'])")
ZONE=$(python3 -c "import json;print(json.load(open('instance-metadata.json'))['compute'].get('zone',''))")
{ echo "name=$NAME"; echo "vmid=$VMID"; echo "region=$REGION"; echo "zone=$ZONE"; echo "size=$SIZE"; echo "captured=$STAMP"; } > metadata.txt
imds "attested/document?api-version=2020-09-01" > imds-attested-document.json   # Azure-signed (PKCS7) instance document, carries region
uname -a > kernel.txt; cat /etc/os-release >> kernel.txt
dmesg | grep -i -E "sev|snp|tdx|memory encryption|tsm|tpm|hyper-v|paravisor" > dmesg-cc.txt || true
ls -l /dev/sev-guest /dev/tdx_guest /dev/tpm0 /dev/tpmrm0 > devices.txt 2>&1 || true

SENTENCE="rats geographic-results: Azure Confidential VM probe answering Sardar and Mandyam, 10 Sep 2026; VM $NAME ($VMID) in $REGION; $STAMP"
printf '%s' "$SENTENCE" > nonce-sentence.txt; printf '%s' "$SENTENCE" | sha512sum | cut -d' ' -f1 > nonce.hex
python3 -c "import binascii;open('nonce.bin','wb').write(binascii.unhexlify(open('nonce.hex').read().strip()))"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq > apt.log 2>&1; apt-get install -y -qq tpm2-tools openssl curl jq ca-certificates >> apt.log 2>&1

# HCL report (paravisor-generated: hardware report + runtime data with the vTPM AK/EK public keys)
tpm2_nvread -C o 0x01400001 -o hcl-report.bin > nv.log 2>&1 || echo "nvread 0x01400001 failed" >> nv.log
tpm2_nvread -C o 0x01400002 -o hcl-runtime-data.bin >> nv.log 2>&1 || true
python3 - <<'PY'
import struct, json, re
b=open("hcl-report.bin","rb").read(); open("hcl-report.hex","w").write(b.hex()+"\n")
info={"size":len(b),"magic":b[:4].decode(errors="replace")}
hdr=struct.unpack_from("<IIII", b, 0) if len(b)>=16 else None; info["header"]=hdr
# hardware report follows the 32-byte HCL header; SNP report is 1184 bytes, TD report 1024 bytes
snp=b[32:32+1184]; ver=struct.unpack_from("<I", snp, 0)[0] if len(snp)>=4 else None; info["hw_report_first_u32"]=ver
kind="snp" if ver in (2,3,4,5) else "tdx"; hw_len=1184 if kind=="snp" else 1024
# var data after the hardware report: u32 total size, a 16-byte sub-header, then the runtime-data JSON (its SHA-256 is REPORT_DATA)
j=b.find(b"{", 32+hw_len); jl=struct.unpack_from("<I", b, j-4)[0] if j>0 else 0; rt=b[j:j+jl] if j>0 else b""
if rt:
    open("hcl-runtime-data.json","wb").write(rt); info["runtime_offset"]=j; info["runtime_len"]=jl
    try: info["runtime_keys"]=list(json.loads(rt).keys())
    except Exception as e: info["runtime_parse"]=repr(e)[:80]
open("hcl-parse.json","w").write(json.dumps(info, indent=1))
if kind=="snp": open("report.bin","wb").write(snp); open("report.hex","w").write(snp.hex()+"\n")
else: open("td-report.bin","wb").write(b[32:32+1024])
open("report-kind.txt","w").write(kind+"\n")
PY
TEE=$(cat report-kind.txt 2>/dev/null || echo unknown); echo "tee=$TEE" >> metadata.txt

if [ "$TEE" = "snp" ]; then
  imds "THIM/amd/certification" > thim-amd-certification.json 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/THIM/amd/certification" > thim-amd-certification.json
  jq -r .vcekCert thim-amd-certification.json > thim-vcek.pem 2>/dev/null; jq -r .certificateChain thim-amd-certification.json > thim-chain.pem 2>/dev/null; jq -r .tcbm thim-amd-certification.json > thim-tcbm.txt 2>/dev/null
  openssl x509 -in thim-vcek.pem -noout -subject -issuer -serial > thim-vcek-summary.txt 2>&1; openssl x509 -in thim-vcek.pem -noout -text 2>/dev/null | grep -A2 -E "3704" >> thim-vcek-summary.txt
  openssl verify -CAfile thim-chain.pem thim-vcek.pem > openssl-verify-vcek.txt 2>&1
else
  python3 - <<'PY'
import base64, json, urllib.request
td=open("td-report.bin","rb").read(); body=json.dumps({"report": base64.urlsafe_b64encode(td).decode().rstrip("=")}).encode()
req=urllib.request.Request("http://169.254.169.254/acc/tdquote", data=body, headers={"Content-Type":"application/json"})
try:
    r=json.load(urllib.request.urlopen(req, timeout=60)); q=r["quote"]; q+= "="*(-len(q)%4); raw=base64.urlsafe_b64decode(q)
    open("quote.bin","wb").write(raw); open("quote.hex","w").write(raw.hex()+"\n"); print("quote bytes", len(raw))
except Exception as e: print("tdquote failed", repr(e)[:200])
PY
fi > tdquote.log 2>&1

# vTPM: persistent handles, EK/AK public parts, EK certificate, and a quote over our nonce with the HCL AK
tpm2_getcap handles-persistent > tpm-handles.txt 2>&1 || true
for h in 0x81000000 0x81000001 0x81000002 0x81000003 0x81010001; do tpm2_readpublic -c $h -o "pub-$h.pem" -f pem > "readpublic-$h.txt" 2>&1 || rm -f "pub-$h.pem" "readpublic-$h.txt"; done
tpm2_nvread -C o 0x01c00002 -o ek-rsa.der > ek.log 2>&1 || echo "no RSA EK cert" >> ek.log
[ -s ek-rsa.der ] && openssl x509 -inform DER -in ek-rsa.der -noout -subject -issuer -serial -dates > ek-summary.txt 2>&1
for h in 0x81000003 0x81000000 0x81000001; do
  if [ -f "pub-$h.pem" ]; then tpm2_quote -c $h -l sha256:0,1,2,3,4,5,6,7 -q "$(head -c 64 nonce.hex)" -m quote-msg.bin -s quote-sig.bin -o quote-pcrs.bin -g sha256 > "tpm-quote-$h.log" 2>&1 && { echo "$h" > quote-ak-handle.txt; break; }; fi
done
tpm2_pcrread sha256 > pcrs.txt 2>&1 || true

# Microsoft Azure Attestation, best effort against the shared regional provider (token issuer is region-scoped)
python3 - <<'PY'
import base64, json, urllib.request, os
def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
region=open("metadata.txt").read().split("region=")[1].split()[0]
short={"eastus":"eus","eastus2":"eus2","westus":"wus","westus2":"wus2","westus3":"wus3","northeurope":"neu","westeurope":"weu","southeastasia":"sasia","uksouth":"uks","centralus":"cus","southcentralus":"scus"}.get(region, region)
url=f"https://shared{short}.{short}.attest.azure.net"
kind=open("report-kind.txt").read().strip(); rt=open("hcl-runtime-data.json","rb").read() if os.path.exists("hcl-runtime-data.json") else b""
if kind=="snp":
    # as Azure's cvm-attestation-tools builds it: report = base64url(JSON{SnpReport, VcekCertChain}), runtimeData = the HCL runtime JSON
    rep=open("report.bin","rb").read(); chain=(open("thim-vcek.pem","rb").read()+open("thim-chain.pem","rb").read()) if os.path.exists("thim-vcek.pem") else b""
    hw=json.dumps({"SnpReport": b64u(rep), "VcekCertChain": b64u(chain)}).encode()
    body={"report": b64u(hw), "runtimeData": {"data": b64u(rt), "dataType": "JSON"}}; ep=f"{url}/attest/SevSnpVm?api-version=2022-08-01"
else:
    q=open("quote.bin","rb").read() if os.path.exists("quote.bin") else b""
    body={"quote": b64u(q), "runtimeData": {"data": b64u(rt), "dataType": "JSON"}}; ep=f"{url}/attest/TdxVm?api-version=2023-04-01-preview"
req=urllib.request.Request(ep, data=json.dumps(body).encode(), headers={"Content-Type":"application/json"})
try:
    r=json.load(urllib.request.urlopen(req, timeout=60)); open("maa-token.jwt","w").write(r["token"]); print("MAA token ok from", url)
except urllib.error.HTTPError as e: print("MAA", e.code, e.read().decode()[:400])
except Exception as e: print("MAA failed", repr(e)[:200])
PY
> maa.log 2>&1

sha256sum hcl-report.bin report.bin td-report.bin quote.bin nonce.bin thim-vcek.pem quote-msg.bin quote-sig.bin ek-rsa.der maa-token.jwt > sha256sums.txt 2>/dev/null
cd /root/probe && tar czf "$STAMP.tgz" "$STAMP" && base64 -w0 "$STAMP.tgz" > "$STAMP.b64"; SZ=$(stat -c%s "$STAMP.b64")
{ echo "===PROBE-BEGIN=== $STAMP $NAME $REGION $TEE size=$SZ"; cat "$STAMP.b64"; echo; echo "===PROBE-END==="; } > /dev/ttyS0 2>/dev/null || true
echo "PROBE DONE $STAMP $NAME $REGION $TEE size=$SZ" | tee /dev/ttyS0 2>/dev/null
