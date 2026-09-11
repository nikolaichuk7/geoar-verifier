#!/bin/bash
# draft-fossati-seat-early-attestation-06, Section 5.1.1 binder measured on SEV-SNP.
# Runs a real TLS 1.3 handshake in the guest (ssl.MemoryBIO), captures the exact
# ClientHello...ServerHello transcript, derives s_attest_binder = HKDF-Expand-Label(
# HKDF-Expand-Label(0,"attestation base",Hash(CH..SH)),"attestation",Hash(server SPKI)),
# and requests a VCEK-signed report (KEY_SEL 1) with REPORT_DATA = binder||0-pad. The server
# TLS identity key (TIK) is injected identically into both guests via metadata: that shared key
# is the leaked key of the intra-handshake.fail / Section 5.2 attacker. The chip that signs is the
# guest's own chip, so two guests give two distinct CHIP_IDs bound to the same key -> the relay.
set -u
exec > >(tee -a /root/probe.log) 2>&1
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/probe/$STAMP; mkdir -p "$OUT"; cd "$OUT"
CLOUD=google; IID=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name); ZONE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}')
ROLE=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/role)
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/tik-pem > tik.pem
{ echo "cloud=$CLOUD"; echo "instance=$IID"; echo "zone=$ZONE"; echo "role=$ROLE"; echo "captured=$STAMP"; echo "probe=early-attest"; } > metadata.txt
uname -a > kernel.txt; dmesg 2>/dev/null | grep -i -E "sev|snp" > dmesg-sev.txt || true

# ensure /dev/sev-guest
if [ ! -e /dev/sev-guest ]; then modprobe sev-guest 2>/dev/null || true; fi
if [ ! -e /dev/sev-guest ]; then export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq linux-modules-extra-$(uname -r) >/dev/null 2>&1; modprobe sev-guest 2>/dev/null || true; fi
n=0; while [ ! -e /dev/sev-guest ] && [ $n -lt 60 ]; do sleep 1; n=$((n+1)); done; ls -l /dev/sev-guest > devices.txt 2>&1 || true

# TIK (shared/leaked) -> self-signed cert + SPKI, exactly as the verifier will read the SPKI
openssl req -x509 -new -key tik.pem -subj "/CN=attester.local" -days 1 -out cert.pem 2>/dev/null
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER -out spki.der 2>/dev/null

# embedded stdlib handshake+binder module
echo "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJHdWVzdC1zaWRlLCBzdGRsaWItb25seTogcnVuIGEgcmVhbCBUTFMgMS4zIGhhbmRzaGFrZSAoc3NsLk1lbW9yeUJJTyksIGNhcHR1cmUgdGhlIGV4YWN0CkNsaWVudEhlbGxvLi4uU2VydmVySGVsbG8gdHJhbnNjcmlwdCwgZGVyaXZlIHRoZSBTZWN0aW9uIDUuMS4xIHNlcnZlciBhdHRlc3RhdGlvbiBiaW5kZXIsIGFuZAp3cml0ZSBSRVBPUlRfREFUQS4gQ2VydC9rZXkvU1BLSSBhcmUgcHJvZHVjZWQgYnkgb3BlbnNzbCBpbiB0aGUgY2FsbGVyIChubyBgY3J5cHRvZ3JhcGh5YCBkZXApLgoKYXJndjogY2VydC5wZW0ga2V5LnBlbSBzcGtpLmRlciBvdXRfcHJlZml4IiIiCmltcG9ydCBzc2wsIHN5cywganNvbiwgaGFzaGxpYiwgaG1hYywgc3RydWN0CgpTVUlURV9IQVNIID0geyJUTFNfQUVTXzI1Nl9HQ01fU0hBMzg0IjogInNoYTM4NCIsICJUTFNfQ0hBQ0hBMjBfUE9MWTEzMDVfU0hBMjU2IjogInNoYTI1NiIsCiAgICAgICAgICAgICAgIlRMU19BRVNfMTI4X0dDTV9TSEEyNTYiOiAic2hhMjU2In0KSEFTSEVTID0geyJzaGEyNTYiOiBoYXNobGliLnNoYTI1NiwgInNoYTM4NCI6IGhhc2hsaWIuc2hhMzg0fQoKZGVmIGhrZGZfZXhwYW5kKHByaywgaW5mbywgbGVuZ3RoLCBobik6CiAgICBoID0gSEFTSEVTW2huXTsgaGxlbiA9IGgoKS5kaWdlc3Rfc2l6ZTsgbiA9IChsZW5ndGggKyBobGVuIC0gMSkvL2hsZW47IHQ9YiIiOyBva209YiIiCiAgICBmb3IgaSBpbiByYW5nZSgxLCBuKzEpOgogICAgICAgIHQgPSBobWFjLm5ldyhwcmssIHQraW5mbytieXRlcyhbaV0pLCBoKS5kaWdlc3QoKTsgb2ttICs9IHQKICAgIHJldHVybiBva21bOmxlbmd0aF0KCmRlZiBoa2RmX2V4cGFuZF9sYWJlbChzZWNyZXQsIGxhYmVsLCBjb250ZXh0LCBsZW5ndGgsIGhuKToKICAgIGZ1bGwgPSBiInRsczEzICIgKyBsYWJlbC5lbmNvZGUoKQogICAgbGJsID0gc3RydWN0LnBhY2soIj5IIiwgbGVuZ3RoKSArIHN0cnVjdC5wYWNrKCJCIiwgbGVuKGZ1bGwpKSArIGZ1bGwgKyBzdHJ1Y3QucGFjaygiQiIsIGxlbihjb250ZXh0KSkgKyBjb250ZXh0CiAgICByZXR1cm4gaGtkZl9leHBhbmQoc2VjcmV0LCBsYmwsIGxlbmd0aCwgaG4pCgpkZWYgc2VydmVyX2JpbmRlcih0cmFuc2NyaXB0LCBzcGtpX2RlciwgaG4pOgogICAgaGxlbiA9IEhBU0hFU1tobl0oKS5kaWdlc3Rfc2l6ZQogICAgYmFzZSA9IGhrZGZfZXhwYW5kX2xhYmVsKGIiXHgwMCIqaGxlbiwgImF0dGVzdGF0aW9uIGJhc2UiLCBIQVNIRVNbaG5dKHRyYW5zY3JpcHQpLmRpZ2VzdCgpLCBobGVuLCBobikKICAgIHJldHVybiBoa2RmX2V4cGFuZF9sYWJlbChiYXNlLCAiYXR0ZXN0YXRpb24iLCBIQVNIRVNbaG5dKHNwa2lfZGVyKS5kaWdlc3QoKSwgaGxlbiwgaG4pCgpkZWYgZmlyc3RfaHNfbXNnKGZsaWdodCwgd2FudCk6CiAgICBpPTA7IGJ1Zj1iIiIKICAgIHdoaWxlIGkrNSA8PSBsZW4oZmxpZ2h0KToKICAgICAgICBjdHlwZT1mbGlnaHRbaV07IHJsZW49aW50LmZyb21fYnl0ZXMoZmxpZ2h0W2krMzppKzVdLCJiaWciKTsgYnVmICs9IGZsaWdodFtpKzU6aSs1K3JsZW5dIGlmIGN0eXBlPT0yMiBlbHNlIGIiIjsgaSs9NStybGVuCiAgICBpZiBsZW4oYnVmKTw0IG9yIGJ1ZlswXSE9d2FudDogcmV0dXJuIE5vbmUKICAgIHJldHVybiBidWZbOjQraW50LmZyb21fYnl0ZXMoYnVmWzE6NF0sImJpZyIpXQoKZGVmIGNhcHR1cmUoY2VydCwga2V5KToKICAgIHNjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX1NFUlZFUik7IHNjdHgubWluaW11bV92ZXJzaW9uPXNjdHgubWF4aW11bV92ZXJzaW9uPXNzbC5UTFNWZXJzaW9uLlRMU3YxXzMKICAgIHNjdHgubG9hZF9jZXJ0X2NoYWluKGNlcnQsIGtleSkKICAgIGNjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCk7IGNjdHgubWluaW11bV92ZXJzaW9uPWNjdHgubWF4aW11bV92ZXJzaW9uPXNzbC5UTFNWZXJzaW9uLlRMU3YxXzMKICAgIGNjdHguY2hlY2tfaG9zdG5hbWU9RmFsc2U7IGNjdHgudmVyaWZ5X21vZGU9c3NsLkNFUlRfTk9ORQogICAgY2luLGNvdXQsc2luLHNvdXQgPSBzc2wuTWVtb3J5QklPKCksc3NsLk1lbW9yeUJJTygpLHNzbC5NZW1vcnlCSU8oKSxzc2wuTWVtb3J5QklPKCkKICAgIGNvYmo9Y2N0eC53cmFwX2JpbyhjaW4sY291dCxzZXJ2ZXJfaG9zdG5hbWU9ImF0dGVzdGVyLmxvY2FsIik7IHNvYmo9c2N0eC53cmFwX2JpbyhzaW4sc291dCxzZXJ2ZXJfc2lkZT1UcnVlKQogICAgY2ZsaWdodD1iIiI7IHNmbGlnaHQ9YiIiCiAgICBmb3IgXyBpbiByYW5nZSgyMCk6CiAgICAgICAgdHJ5OiBjb2JqLmRvX2hhbmRzaGFrZSgpCiAgICAgICAgZXhjZXB0IHNzbC5TU0xXYW50UmVhZEVycm9yOiBwYXNzCiAgICAgICAgZD1jb3V0LnJlYWQoKTsgY2ZsaWdodCs9ZDsgc2luLndyaXRlKGQpCiAgICAgICAgdHJ5OiBzb2JqLmRvX2hhbmRzaGFrZSgpCiAgICAgICAgZXhjZXB0IHNzbC5TU0xXYW50UmVhZEVycm9yOiBwYXNzCiAgICAgICAgZD1zb3V0LnJlYWQoKTsgc2ZsaWdodCs9ZDsgY2luLndyaXRlKGQpCiAgICAgICAgaWYgY29iai5jaXBoZXIoKSBhbmQgc29iai5jaXBoZXIoKTogYnJlYWsKICAgIHN1aXRlPXNvYmouY2lwaGVyKClbMF07IGhuPVNVSVRFX0hBU0guZ2V0KHN1aXRlLCJzaGEzODQiKQogICAgY2g9Zmlyc3RfaHNfbXNnKGNmbGlnaHQsMSk7IHNoPWZpcnN0X2hzX21zZyhzZmxpZ2h0LDIpCiAgICBhc3NlcnQgY2ggYW5kIHNoLCAoY2ggaXMgbm90IE5vbmUsIHNoIGlzIG5vdCBOb25lLCBzdWl0ZSkKICAgIHJldHVybiBjaCtzaCwgaG4sIHN1aXRlCgppZiBfX25hbWVfXz09Il9fbWFpbl9fIjoKICAgIGNlcnQsa2V5LHNwa2lfcGF0aCxwcmVmID0gc3lzLmFyZ3ZbMTo1XQogICAgc3BraT1vcGVuKHNwa2lfcGF0aCwicmIiKS5yZWFkKCkKICAgIHRyLGhuLHN1aXRlPWNhcHR1cmUoY2VydCxrZXkpCiAgICBiaW5kZXI9c2VydmVyX2JpbmRlcih0cixzcGtpLGhuKTsgcmQ9YmluZGVyK2IiXHgwMCIqKDY0LWxlbihiaW5kZXIpKQogICAgb3BlbihwcmVmKyItdHJhbnNjcmlwdC5iaW4iLCJ3YiIpLndyaXRlKHRyKQogICAgb3BlbihwcmVmKyItcmVwb3J0ZGF0YS5iaW4iLCJ3YiIpLndyaXRlKHJkKQogICAganNvbi5kdW1wKHsic3VpdGUiOnN1aXRlLCJoYXNoIjpobiwidHJhbnNjcmlwdF9sZW4iOmxlbih0ciksInRyYW5zY3JpcHRfc2hhMjU2IjpoYXNobGliLnNoYTI1Nih0cikuaGV4ZGlnZXN0KCksCiAgICAgICAgICAgICAgICJzcGtpX3NoYTI1NiI6aGFzaGxpYi5zaGEyNTYoc3BraSkuaGV4ZGlnZXN0KCksImJpbmRlciI6YmluZGVyLmhleCgpLCJyZXBvcnRfZGF0YSI6cmQuaGV4KCl9LAogICAgICAgICAgICAgIG9wZW4ocHJlZisiLWhzLmpzb24iLCJ3IikpCiAgICBwcmludCgiT0sgc3VpdGUiLHN1aXRlLCJoYXNoIixobiwidHIiLGxlbih0ciksImJpbmRlciIsYmluZGVyLmhleCgpWzoyNF0pCg==" | base64 -d > hs.py
python3 hs.py cert.pem tik.pem spki.der cap
# cap-reportdata.bin now holds REPORT_DATA = s_attest_binder || 0-pad ; cap-transcript.bin the CH..SH bytes

python3 - <<'PYIOCTL'
import ctypes, fcntl, os, struct, json, uuid
RD = open("cap-reportdata.bin","rb").read(); assert len(RD)==64
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
# KEY_SEL 1 = VCEK (per-chip identity), REPORT_DATA = the 5.1.1 binder
req=Req(); ctypes.memmove(req.user_data, RD, 64); req.vmpl=0; req.flags=1
resp=Resp(); io=Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0); err=None
fd=os.open("/dev/sev-guest", os.O_RDWR)
try: fcntl.ioctl(fd, SNP_GET_REPORT, io)
except OSError as e: err=f"errno {e.errno} {e.strerror}"
os.close(fd)
rep=bytes(resp.report[:1184]); ok = err is None and resp.report_size==1184 and struct.unpack_from("<I",rep,0)[0] in (2,3,4,5)
r={"name":"binder","key_sel":1,"ioctl_error":err,"exitinfo2":hex(io.exitinfo2),"fw_status":resp.status,"ok":ok}
if ok: r.update(parse(rep)); open("report-binder.bin","wb").write(rep)
results["binder"]=r
# extended report for the cert table (VCEK/ASK/ARK)
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
print("REPORT ok=", results["binder"]["ok"], "chip=", results["binder"].get("chip_id_prefix"), "signing=", results["binder"].get("signing_key"))
PYIOCTL

for f in cert-*.bin; do [ -f "$f" ] && { echo "== $f"; openssl x509 -inform DER -in "$f" -noout -subject -issuer 2>/dev/null || openssl x509 -inform PEM -in "$f" -noout -subject -issuer 2>/dev/null; }; done > certs-summary.txt 2>&1
curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vcek/v1/Milan/cert_chain -o kds-vcek-cert_chain.pem 2>/dev/null || true
rm -f tik.pem   # do not ship the private key off the guest
sha256sum report-*.bin cap-*.bin spki.der cert-*.bin kds-*.pem metadata.txt > sha256sums.txt 2>/dev/null
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
