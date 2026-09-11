# Results: SEV-SNP on a host we control (11 September 2026)

Everything measured on the clouds so far had one gap: the hypervisor's own settings are invisible from
inside a guest. On AWS shared tenancy we saw `KEY_SEL = 1` refused with `INVALID_KEY` and CHIP_ID zeroed,
and *inferred* from the ABI that the host launches guests with `VCEK_DIS` and sets `MASK_CHIP_ID`. This
run removes the inference: the host is ours, so each switch is set deliberately, one at a time.

## Machine

Rented by the hour: Supermicro H13SST-G, **AMD EPYC 9124 (Genoa)**, 64 GB, Chicago. BIOS (AMI 3.2) changed
for this work: `SEV-ES ASID Space Limit` 1 → 30 (at 1 the firmware allows *no* SEV-ES or SNP guests),
`SNP Memory (RMP Table) Coverage` and `SMEE` Auto → Enabled, `IOMMU` and `SEV-SNP Support` Auto → Enabled.
Host: Ubuntu 24.04, kernel 6.17.0-23, `kvm_amd: SEV-SNP enabled (ASIDs 1 - 29)`, firmware API 1.55 build 40,
QEMU 10.1.2 built from source, OVMF `ovmf-amdsev` 2026.05. Guest: Ubuntu 24.04 cloud image, our
`probe-dual.sh` unchanged from the cloud runs.

Host identity, read through `/dev/sev` with `SEV_GET_ID2` (`snp_platform.py id`):

    2d2b2dd3abfaa380b70dd1bfcd9bd7755d9c323b20978dcfa22849a1223745882ca516b528383035ff0b47f5188f6b396397d625f7e8445772026fd85d6b2854

## The four experiments

| | E1 baseline | E2 `vcek-disabled=on` | E3 `MASK_CHIP_ID=1` | E4 both |
|---|---|---|---|---|
| host `mask_chip_id` / `vlek_en` | 0 / 0 | 0 / 0 | **1** / 0 | **1** / 0 |
| KEY_SEL 0 (firmware default) | VCEK | **INVALID_KEY 0x27** | VCEK | **0x27** |
| KEY_SEL 1 (VCEK) | VCEK | **INVALID_KEY 0x27** | VCEK | **0x27** |
| KEY_SEL 2 (VLEK) | 0x27 (no VLEK loaded) | 0x27 | 0x27 | 0x27 |
| CHIP_ID in the report | `2d2b2dd3…` | — | **all zeros** | — |
| MASK_CHIP_KEY bit in FLAGS | 0 | — | 0 | — |
| chained pair (B carries SHA-512 of A, same REPORT_ID) | verifies | — | verifies | — |
| channel binding (Ed25519 key in REPORT_DATA, signs the nonce) | verifies | — | verifies | — |
| reports verify under the KDS VCEK for **Genoa**, chain to ARK, hwID == CHIP_ID | yes, 5/5 | — | see below | — |

## What this settles

1. **The AWS refusal is reproduced, and the cause is isolated.** With `VCEK_DIS` set at launch and no VLEK
   loaded, *every* key selection is refused with `0x27` — and that is exactly the ABI's rule set: KEY_SEL 1
   with VcekDis; KEY_SEL 2 with no VLEK; KEY_SEL 0 with both. AWS refuses only KEY_SEL 1 and serves 0 and 2,
   which is the same rule set with a VLEK present. So AWS shared tenancy = `VCEK_DIS` set **and** a VLEK
   loaded. We could not load a VLEK to close the last gap: AMD issues VLEK hashsticks only to enrolled
   cloud providers (ABI 3.7), which is itself the point about who the key domain belongs to.
2. **The zeroed CHIP_ID is a host setting, not a property of the key.** In E3 the reports are still
   VCEK-signed and still verify, but CHIP_ID is all zeros, and `MASK_CHIP_KEY` in the report FLAGS stays 0.
   A Relying Party cannot tell from the report alone why the field is empty.
3. **Masking hides the chip from the guest, not from the operator, and the identifiers line up.** The guest
   in E3 cannot fetch its own certificate: it has no hwID to ask KDS with. Using the **host's** `SEV_GET_ID2`
   value instead, AMD KDS issues a VCEK whose `hwID` equals that value, and it verifies E3's masked report,
   chain to ARK-Milan. In E1, unmasked, the guest's CHIP_ID **is byte-identical to the host's GET_ID**. That
   is the answer to the CHIP_ID / hwID question in the RATS thread, measured on both sides of the boundary
   for the first time in this corpus: one value, two names, and the host keeps it when the guest is denied it.

## Files

`runs/E1..E4.console` (raw guest serial output), `runs/E1..E4/<stamp>/` (the decoded archive: reports,
`dual-results.json`, nonce sentence, kernel and dmesg), `runs/E*-host-status.json` and `runs/E1-host-id.json`
(the host's `SNP_PLATFORM_STATUS` and `SEV_GET_ID2` at the time of each run). Verified with
`../aws-vlek/dual_verify.py`, which picks the KDS product (Milan / Genoa / Turin) from the report itself.

## Attempt log

The guest would not start until three things were right, none of them documented together anywhere we found.
`reduced-phys-bits` must be **6** on this part (CPUID 0x8000001F EBX bits 11:6); the widely copied
`reduced-phys-bits=1` makes the guest fault on the APIC page at the reset vector with "Convert non
guest_memfd backed memory region (0xfee00000) to private", which looks like a firmware or kernel bug and is
not one. The firmware must be an AmdSev build (Ubuntu 24.04's 2024.02 OVMF is too old; the `ovmf-amdsev`
package from 2026.05 works), loaded with `-bios`, since an SNP guest has no read-only memslots for pflash.
And the Ubuntu cloud image ships no `sev-guest` driver at all, so `/dev/sev-guest` never appears until
`linux-modules-extra-$(uname -r)` is installed inside the guest.
