#!/bin/bash
# Launch one SEV-SNP guest for an experiment and collect its probe archive. Run as root on the host.
# Usage: ./run-guest.sh E1|E2|E3|E4 [site]   (site defaults to cherry-chicago; env OVMF, CPU_MODEL, CBITPOS, RPB override firmware, CPU model, C-bit, phys-bit reduction.
# cbitpos and RPB must match CPUID 0x8000001F EBX: bits 5:0 = C-bit (51 here), bits 11:6 = reduced phys bits (6 here).
# Passing reduced-phys-bits=1, as many published examples do, makes the guest fault on the APIC page at the reset vector.)
# The firmware is loaded with -bios, not pflash: an SEV-SNP VM has no read-only memslots and QEMU refuses pflash for it.
# -bios needs one whole image, so host-setup.sh concatenates OVMF_VARS_4M.fd + OVMF_CODE_4M.fd into /root/snp/OVMF_4M.fd (4 MiB).
#   E1 baseline; E2 QEMU sev-snp-guest vcek-disabled=on; E3 platform MASK_CHIP_ID=1; E4 both.
set -u; R=/root/snp; cd $R; EXP=${1:?E1..E4}; SITE=${2:-cherry-chicago}; . ./qemu.env; STAMP=$(date -u +%Y%m%dT%H%M%SZ); D=$R/runs/$EXP-$STAMP; mkdir -p $D
case $EXP in E1) MASK=0; VDIS=;; E2) MASK=0; VDIS=",vcek-disabled=on";; E3) MASK=1; VDIS=;; E4) MASK=1; VDIS=",vcek-disabled=on";; *) echo "unknown experiment"; exit 1;; esac
# E4 also supplies HOST_DATA (32 bytes the hypervisor hands to the firmware; zeros on every cloud we measured) so that the guest's report shows it at offset 0xC0
[ "$EXP" = E4 ] && VDIS="$VDIS,host-data=$(printf 'rats geographic-results: HOST_DATA set by our own hypervisor' | sha256sum | cut -c1-64 | xxd -r -p | base64 -w0)"
python3 snp_platform.py config $MASK > $D/host-config-set.json; python3 snp_platform.py status > $D/host-status.json; python3 snp_platform.py id > $D/host-id.json
cat $D/host-status.json | python3 -c "import json,sys; s=json.load(sys.stdin); print('host: api', s['api'], 'mask_chip_id', s['mask_chip_id'], 'mask_chip_key', s['mask_chip_key'], 'vlek_en', s['vlek_en'], 'reported_tcb', s['reported_tcb'])"
# guest disk (fresh copy of the cloud image) and cloud-init seed: the probe plus its environment file
qemu-img create -q -f qcow2 -b $R/noble.img -F qcow2 $D/guest.qcow2 20G
GUEST=rats-$EXP-$(echo $STAMP | tr -d 'TZ' | cut -c9-14)
cat > $D/user-data <<UD
#cloud-config
hostname: $GUEST
write_files:
  - path: /etc/probe-env
    content: |
      CLOUD=baremetal
      IID=$GUEST
      ZONE=$SITE
  - path: /root/probe-dual.sh
    permissions: '0755'
    encoding: b64
    content: $(base64 -w0 $R/probe-dual.sh)
runcmd:
  - [ bash, -c, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq linux-modules-extra-\$(uname -r) >/dev/null 2>&1; modprobe sev-guest 2>/dev/null || true; n=0; while [ ! -e /dev/sev-guest ] && [ \$n -lt 60 ]; do sleep 1; n=\$((n+1)); done; ls -l /dev/sev-guest; /root/probe-dual.sh; sleep 5; poweroff" ]
UD
printf 'instance-id: %s\nlocal-hostname: %s\n' "$GUEST" "$GUEST" > $D/meta-data; cloud-localds $D/seed.iso $D/user-data $D/meta-data
echo "launching $GUEST ($EXP, MASK_CHIP_ID=$MASK$VDIS)"; echo "$QEMU sev-snp-guest$VDIS" > $D/qemu-cmdline.txt
timeout 900 $QEMU -enable-kvm -cpu "${CPU_MODEL:-EPYC-Genoa}" -smp 2 -m 4G -machine q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off,kernel-irqchip=split \
  -object memory-backend-memfd,id=ram1,size=4G,share=true,prealloc=false \
  -object sev-snp-guest,id=sev0,cbitpos=${CBITPOS:-51},reduced-phys-bits=${RPB:-6},policy=0x30000$VDIS \
  -bios "${OVMF:-/root/snp/OVMF_4M.fd}" \
  -drive file=$D/guest.qcow2,if=virtio -drive file=$D/seed.iso,if=virtio,format=raw \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 -nographic -serial file:$D/guest.console -monitor none -display none > $D/qemu.log 2>&1
echo "qemu exit $?"; grep -c "PROBE DONE" $D/guest.console; python3 snp_platform.py config 0 > /dev/null   # leave the platform unmasked
echo "archive: decode on the operator's machine with tools/decode_console.py $D/guest.console"
