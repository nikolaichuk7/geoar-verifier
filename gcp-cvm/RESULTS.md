# Results: Google Cloud Confidential VMs, SEV-SNP (VCEK) and Intel TDX (11 September 2026)

Four Ubuntu 24.04 Confidential VMs, two per TEE, two zones per TEE, plus two
Container-Optimized OS VMs for the Google attestation token (see the last row). Every VM was
deleted after collection; nothing is left running. Every hardware report carries our public
nonce (REPORT_DATA / REPORTDATA = SHA-512 of `nonce-sentence.txt`).

## Hardware layer: the chip's own signed statement

| | SEV-SNP us-central1-b | SEV-SNP europe-west4-a | TDX us-central1-a | TDX europe-west4-a |
|---|---|---|---|---|
| machine | n2d-standard-2 (Milan) | n2d-standard-2 (Milan) | c3-standard-4 | c3-standard-4 |
| how the report was read | `SNP_GET_REPORT` ioctl on `/dev/sev-guest`, 20 lines of Python, no library; identical bytes from configfs-tsm | same | configfs-tsm `tsm/report` outblob | same |
| signing key | VCEK (flags 0x48 = 0) | VCEK | ECDSA-P256 attestation key certified by the QE, PCK, Intel SGX Root CA | same |
| chain verified from | AMD KDS, live, ASK/ARK | AMD KDS, live | PCK chain embedded in the quote; root byte-identical to Intel's published root | same |
| CHIP_ID / platform identity | present, `f1cf2d6f…`; VCEK **hwID == CHIP_ID** | present, `15f90cb0…`; hwID == CHIP_ID | PCK certificate (FMSPC, PPID-derived), no chip serial in the quote | same |
| HOST_DATA | zeros | zeros | n/a | n/a |
| nonce | matches | matches | matches | matches |
| **anything locational in the signed bytes** | **nothing** | **nothing** | **nothing** | **nothing** |

## Platform layer: what Google signs about the same VM

| artifact | signer | verified how | what it says about place | RFC 9334 class |
|---|---|---|---|---|
| vTPM EK certificates (RSA and ECC), TPM NV 0x01c00002 / 0x01c0000a | `EK/AK CA Intermediate` under `EK/AK CA Root`, Google Cloud | issuer fetched via AIA, signature OK on all 8 certificates | subject `L=<zone>` (e.g. `L=europe-west4-a`); extension 1.3.6.1.4.1.11129.2.1.21 = {zone, project number, project id, instance id, instance name} | Endorsement |
| Compute Engine identity token (JWT) | `accounts.google.com`, RS256 | JWKS via OpenID discovery, signature OK on all 4 | `google.compute_engine.zone`, `instance_id`, `project_id` | Endorsement |
| Google Cloud Attestation token (`gotpm token`) | Google attestation verifier | see below | `submods.gce.zone`, `hwmodel` | Attestation Result |

The attestation verifier refused the Ubuntu VMs: TDX "no GRUB measurements found", SEV-SNP
"unexpected_snp_attestation". The COS runs (`runs/*-cos/`) record whether Google's own image
gets the token; their outcome is in `runs/summary.json` and in the log excerpts kept per run.

## What this settles

1. **Two silicon vendors, four machines, zero locational bytes in the hardware report.** SEV-SNP
   identifies the chip (CHIP_ID, and the VCEK hwID is the same value, checked). TDX identifies the
   platform class through the PCK certificate. Neither says where it is.
2. **Google states the zone three times, and every one of them is an Endorsement:** the vTPM EK
   certificate (a CA statement about a key, with the zone in the subject and in a structured
   extension), the identity token (an identity-provider statement about the VM), and the
   attestation token where issued (a Verifier's statement that folds in Google's inventory).
3. **The same VM therefore yields two geographic Attestation Results of different class.** A
   Verifier that reads the EK certificate emits `jurisdiction-country` NL with `basis =
   endorsement`; one that consumes Google's token emits the same NL with `basis =
   attestation-result` and a `basis-ref` if the token can be referenced; one that has only the
   TDX quote emits nothing. Without `basis` the three are indistinguishable on the wire.
4. **Against Sardar's identity question:** on Google the operator identity is not in the chip's
   report either; it is in Google's CA and identity-provider statements, the same place as the zone.

## Files per run (`runs/<name>/<stamp>/`)

`report.bin/.hex` or `quote.bin/.hex`, `tsm-outblob.bin/.hex`, `request-file.bin`,
`nonce-sentence.txt`, `nonce.hex`, `ek-rsa.der`, `ek-ecc.der`, `ek-*-issuer.der` (fetched by the
verifier), `ek-summary.txt`, `gce-identity-token.jwt`, `gcp-attestation-token.jwt` (where issued),
`gotpm-*.log`, `kds-vcek.der` (SEV-SNP), `pck-chain.pem` (TDX), `metadata.txt`, `kernel.txt`,
`dmesg-cc.txt`, `devices.txt`, `snp-ioctl.log`, `tsm-provider.txt`, `sha256sums.txt`.
Not published: raw consoles, package and build logs.

## Attempt log

00:48Z `us-central1-a` had no n2d capacity for SEV-SNP (`resource_availability`); `us-central1-b`
did. 00:48–00:50Z four Ubuntu VMs launched; all four reported within ~70 s of boot. 00:53Z second
pair with an in-tree gotpm build: token refused by the verifier (messages above). 00:58Z COS pair.
