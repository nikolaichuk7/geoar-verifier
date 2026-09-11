#!/bin/bash
# Bare-metal SEV-SNP host preparation (Ubuntu 24.04, run as root). Idempotent; prints a report at the end.
# Stages: 0 facts, 1 firmware/BIOS check, 2 host kernel with SNP support (HWE), 3 QEMU >= 9.1 (built from source
# if the distribution's is older), 4 OVMF, 5 guest image + tools, 6 snphost (optional). Re-run after a reboot.
set -u; export DEBIAN_FRONTEND=noninteractive; R=/root/snp; mkdir -p $R; cd $R
stage() { echo; echo "=== $*"; }
stage "0 facts"; lscpu | grep -E "Model name|Socket|Core|Flags" | sed 's/Flags:.*sev/Flags: ...sev/' | cut -c1-120; grep -o -w "sev\|sev_es\|sev_snp" /proc/cpuinfo | sort -u | tr '\n' ' '; echo; uname -r
stage "1 firmware / BIOS"; dmesg | grep -i -E "sev|snp|rmp|ccp" | head -20; ls -l /dev/sev 2>&1
if dmesg | grep -q -i "SEV-SNP: RMP table physical range"; then echo "RMP table present: SNP enabled in BIOS"; elif dmesg | grep -q -i "SNP.*disabled\|RMP table not"; then echo "!! SNP not enabled in BIOS (RMP table missing): enable SEV/SEV-ES/SEV-SNP/SMEE/IOMMU in the BIOS via the KVM console"; fi
stage "2 host kernel"; K=$(uname -r); MAJ=${K%%.*}; MIN=$(echo "$K" | cut -d. -f2)
if [ "$MAJ" -gt 6 ] || { [ "$MAJ" -eq 6 ] && [ "$MIN" -ge 11 ]; }; then echo "kernel $K has KVM SEV-SNP host support (>= 6.11)"; else
  echo "kernel $K predates SNP host support: installing the HWE kernel"; apt-get update -qq; apt-get install -y -qq linux-generic-hwe-24.04 > apt-kernel.log 2>&1 && echo "HWE kernel installed: REBOOT, then re-run this script" ; fi
cat /sys/module/kvm_amd/parameters/sev_snp 2>/dev/null | sed 's/^/kvm_amd sev_snp=/'; grep -q "kvm_amd.sev=1" /proc/cmdline || echo "note: add kvm_amd.sev=1 kvm_amd.sev_snp=1 to GRUB_CMDLINE_LINUX if the parameters read N after reboot"
stage "3 QEMU"; apt-get install -y -qq qemu-system-x86 qemu-utils cloud-image-utils python3 git build-essential ninja-build pkg-config libglib2.0-dev libpixman-1-dev libslirp-dev python3-venv flex bison > apt-qemu.log 2>&1
QV=$(qemu-system-x86_64 --version | head -1 | grep -o "version [0-9.]*" | cut -d' ' -f2); echo "distribution QEMU $QV"
if qemu-system-x86_64 -object sev-snp-guest,help 2>&1 | grep -q vcek-disabled; then echo "distribution QEMU supports sev-snp-guest with vcek-disabled"; QEMU=qemu-system-x86_64; else
  echo "building QEMU 9.2.4 (sev-snp-guest with vcek-disabled)"; [ -d qemu-9.2.4 ] || { curl -sSL https://download.qemu.org/qemu-9.2.4.tar.xz | tar xJ; }
  ( cd qemu-9.2.4 && ./configure --target-list=x86_64-softmmu --enable-kvm --enable-slirp --disable-docs --disable-werror > ../qemu-configure.log 2>&1 && make -j"$(nproc)" > ../qemu-make.log 2>&1 ) && QEMU=$R/qemu-9.2.4/build/qemu-system-x86_64 && $QEMU --version | head -1 && $QEMU -object sev-snp-guest,help 2>&1 | grep -E "vcek-disabled|id-block" ; fi
echo "QEMU=${QEMU:-missing}" > qemu.env
stage "4 OVMF"; apt-get install -y -qq ovmf > apt-ovmf.log 2>&1; ls -l /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd 2>/dev/null; dpkg -s ovmf | grep -i "^Version"
stage "5 guest image"; [ -f noble.img ] || curl -sSL -o noble.img https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img; qemu-img info noble.img | head -3
stage "6 snphost (optional)"; command -v cargo >/dev/null || { curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal > rustup.log 2>&1; }; export PATH="$HOME/.cargo/bin:$PATH"
[ -x snphost/target/release/snphost ] || { git clone -q https://github.com/virtee/snphost.git 2>/dev/null; ( cd snphost && cargo build -r > ../snphost-build.log 2>&1 ); }; ls -l snphost/target/release/snphost 2>/dev/null
stage "platform status (our own ioctl)"; python3 /root/snp/snp_platform.py status; python3 /root/snp/snp_platform.py id
stage "done"; echo "next: ./run-guest.sh E1  (baseline), E2 (vcek-disabled), E3 (mask_chip_id), E4 (both)"
