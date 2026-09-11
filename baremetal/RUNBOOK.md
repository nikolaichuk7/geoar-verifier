# Bare metal SEV-SNP: the host is ours (runbook, to execute once a server exists)

Goal: reproduce on our own host what the clouds hide from their guests. Launch SEV-SNP guests with the
hypervisor flags the ABI gives the host, and take the same measurements from inside:

| experiment | host setting | expected in the guest | what it proves |
|---|---|---|---|
| E1 baseline | defaults | KEY_SEL 0/1 → VCEK, KEY_SEL 2 → INVALID_KEY (no VLEK), CHIP_ID present | a plain host behaves like Google/Azure |
| E2 VCEK disabled | QEMU `sev-snp-guest` with `vcek-disabled=on` | KEY_SEL 1 → INVALID_KEY 27h, KEY_SEL 0 → INVALID_KEY too (no VLEK loaded) | the AWS refusal reproduced by the documented flag, not inferred |
| E3 chip id masked | platform MASK_CHIP_ID = 1 (SNP_CONFIG via the host `sev` device, e.g. `snphost`) | CHIP_ID all zeros, VCEK still verifies when the Verifier knows the chip id from the host | AWS's second half reproduced |
| E4 both | E2 + E3 | AWS shared tenancy, minus the VLEK | the complete shared-tenancy profile on a machine we control |
| E5 new generation | Genoa (9004) or Turin (9005) host | KDS product name changes (`/vcek/v1/Genoa/…`), same ABI | the atlas gains a generation row |

VLEK cannot be tested here: the hashstick is issued by AMD KDS only to enrolled CSPs (ABI Section 3.7).

## Server

- Provider with BIOS access and hourly billing: Cherry Servers (EPYC 9124P Genoa, ~$0.7/h, "out-of-band KVM
  opens a BIOS-level console") is the first choice; Latitude.sh has Genoa and Turin plans hourly but does not
  document BIOS access. Order with Ubuntu 24.04 (or 25.04 for a newer kernel) and the operator's SSH public key.
- BIOS: enable SEV, SEV-ES, SEV-SNP (AMD CBS → CPU Common → SEV/SNP options), SMEE, IOMMU; set "SNP Memory
  Coverage" enabled if offered; save and reboot. Without BIOS access the host kernel reports `SEV-SNP: RMP table
  not present` and the experiment stops here.

## Host software

1. Kernel with SEV-SNP host support (upstream since 6.11; Ubuntu 24.04 HWE 6.11+ or 25.04's 6.14). Check:
   `dmesg | grep -i -E "sev|snp|rmp"` must show `SEV-SNP enabled` / `ccp ... SEV API` lines; `/dev/sev` exists.
2. QEMU 9.2 or newer (`qemu-system-x86_64 -object sev-snp-guest,help` lists `vcek-disabled`); OVMF built with
   SNP support (`AmdSev` or the distribution's `OVMF.amdsev.fd` / `ovmf-ia32`?) — use the `ovmf` package's
   `OVMF_CODE_4M.secboot.fd` only if it advertises SNP; otherwise build edk2 AmdSevX64.
3. `snphost` (virtee) for platform status and config: `snphost show identifier` (the CHIP_ID), `snphost show tcb`,
   and SNP_CONFIG changes (mask chip id).
4. Guest image: Ubuntu 24.04 cloud image (kernel 6.8 has the sev-guest driver) plus cloud-init seed that runs
   our `probe-dual.sh` and writes the archive to the serial console; the host captures the serial log to a file,
   `tools/decode_console.py` reassembles it, `aws-vlek/dual_verify.py` verifies (KDS fetch by CHIP_ID and TCB).

## Guest launch (E1; E2 adds `,vcek-disabled=on`)

    qemu-system-x86_64 -enable-kvm -cpu EPYC-Genoa -machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
      -object memory-backend-memfd,id=ram1,size=4G,share=true,prealloc=false \
      -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000 \
      -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on -drive file=guest.qcow2,if=virtio \
      -drive file=seed.iso,if=virtio -nographic -serial file:guest-E1.console -smp 2

## Record

Same rules as the clouds: public nonce in the sentence, raw reports and certificates kept, KDS certificates
fetched on the operator's machine, every signature verified before a row enters ATLAS.md and LEDGER.md; the
host's own `snphost show identifier` output is recorded next to the guest's CHIP_ID so that E3 can be checked.
