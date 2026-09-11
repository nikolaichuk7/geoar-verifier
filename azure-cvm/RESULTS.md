# Results: Azure Confidential VMs, SEV-SNP through the paravisor (11 September 2026)

`Standard_DC2as_v5`, Ubuntu 24.04 CVM image, East US and West Europe, two passes (the second
only to obtain the MAA token with the request format Azure's own tool uses). All VMs deleted
after collection. Intel TDX (`DCesv5`) is not offered to this subscription in any commercial
region and is recorded as unavailable, not measured.

## Hardware layer

| | East US | West Europe |
|---|---|---|
| VM | rats-snp-eastus (d01d9654…) | rats-snp-westeurope (5a3c9c0d…) |
| how the report was read | TPM NV 0x01400001, the HCL report the paravisor produced at boot (header `HCLA`, version 2 / 1, report size 2469 / 2346) | same |
| SEV-SNP report | version 3, policy 0x3001f, flags 0x48 = 0: **VCEK**, MASK_CHIP_KEY 0, AUTHOR_KEY_EN 0 | same |
| CHIP_ID | present, `24f37eaa…` | present, `92a89c01…` |
| HOST_DATA | zeros | zeros |
| REPORT_DATA | = SHA-256 of the runtime-data JSON (checked) | checked |
| report signature | OK with the THIM VCEK | OK |
| VCEK chain | SEV-VCEK ← SEV-Milan ← ARK-Milan, OK; **hwID == CHIP_ID** | same |
| THIM VCEK vs live KDS VCEK | same public key; different certificate (THIM issued 2025-01-26, KDS re-issued 2026-09-10), same TCB DB18000000000004 | same pattern (THIM 2025-01-23) |
| **anything locational in the signed bytes** | **nothing** | **nothing** |

## Freshness through the vTPM

The report's REPORT_DATA is fixed at boot (it binds the runtime JSON), so freshness comes from
the vTPM: the runtime JSON carries `HCLAkPub`; the persistent AK 0x81000003 signed a TPM quote
whose extraData is our public nonce (SHA-512 of `nonce-sentence.txt`, first 32 bytes); the quote
verifies with `HCLAkPub` (RSASSA-PKCS1-v1_5, SHA-256) in both regions. Chain: chip → REPORT_DATA
→ runtime JSON → AK → nonce.

## Platform layer: what Azure signs about the same VM

| artifact | signer | says about place | class |
|---|---|---|---|
| IMDS attested document (PKCS#7) | `CN=metadata.azure.com`, Microsoft | `vmId`, `subscriptionId`, `sku=cvm`, timestamps; **no region** | Endorsement (identity, not place) |
| HCL runtime data (inside REPORT_DATA) | bound by the chip, produced by the paravisor | vTPM keys, `vmUniqueId`, secure-boot/TPM flags; **no region** | Evidence-bound configuration |
| Microsoft Azure Attestation token | the shared regional provider (`sharedeus.eus` / `sharedweu.weu`) | the **issuer URL is region-scoped**; claims name the TEE, `vmId`, runtime data | Attestation Result |

The MAA token was obtained in the second pass with the request built the way Azure's own
`cvm-attestation-tools` builds it (`report` = base64url of `{SnpReport, VcekCertChain}`,
`runtimeData` = the HCL runtime JSON); the first pass sent the raw report and was refused with
`InvalidQuote`. West Europe token (`runs/rats-snp-westeurope-2/`): issuer
`https://sharedweu.weu.attest.azure.net`, RS256, signature verified against the provider's
`/certs`, signer certificate `CN=https://sharedweu.weu.attest.azure.net`; claims
`x-ms-attestation-type = sevsnpvm`, `x-ms-compliance-status = azure-compliant-cvm`, and the
full `x-ms-sevsnpvm-*` set (chip id, launch measurement, report data, SVNs, policy bits) plus
`x-ms-runtime` echoing the runtime JSON; **no claim names a region**, the region is the
issuer's address only. The East US second-pass VM produced its token too (`MAA token ok from
https://sharedeus.eus.attest.azure.net` in its log), but its archive was lost: the boot
diagnostics blob was never created for that VM, and the operator deleted the resource group
before an SSH fetch had actually succeeded. A third East US pass (`runs/rats-snp-eastus-3/`)
repeated the capture: token from `https://sharedeus.eus.attest.azure.net`, signature verified,
`sevsnpvm` / `azure-compliant-cvm`, chip `294602de…`, report signature, chain, hwID, runtime
binding and vTPM quote all verified. `collect.sh` now falls back to SSH when the serial log
stays empty, and nothing is deleted before the archive's content has been checked.

Final tally on Azure: 4 hardware reports (2 regions × 2 passes), 4 vTPM quotes over our nonce,
2 MAA tokens (one per region), every check green in `runs/summary.json`.

## What this settles

1. **Third silicon path, same answer.** Azure's SEV-SNP report, read through the paravisor's NV
   index rather than a guest ioctl, is VCEK-signed with CHIP_ID present and no locational byte.
2. **The only region-bearing signed artifact on Azure is the MAA token, and it carries the
   region as the issuer's address, not as a claim about the machine.** Both the attested
   document and the runtime data name the VM, not the place.
3. **VCEK certificates are re-issued.** The chip identity is stable (same key, same hwID) while
   the certificate bytes differ between THIM's cache and a live KDS fetch; a Verifier that pins
   certificate hashes rather than keys would wrongly reject one of them.

## Files per run (`runs/<name>/<stamp>/`)

`hcl-report.bin/.hex`, `report.bin/.hex`, `hcl-runtime-data.json`, `hcl-parse.json`,
`thim-amd-certification.json`, `thim-vcek.pem`, `thim-chain.pem`, `thim-tcbm.txt`,
`openssl-verify-vcek.txt`, `quote-msg.bin`, `quote-sig.bin`, `quote-pcrs.bin`, `pcrs.txt`,
`pub-0x81000003.pem` and other public parts, `tpm-handles.txt`, `imds-attested-document.json`,
`imds-attested.p7b`, `maa-token.jwt` (second pass), `maa.log`, `nonce-sentence.txt`,
`nonce.hex`, `nonce.bin`, `metadata.txt`, `kernel.txt`, `dmesg-cc.txt`, `sha256sums.txt`.
Not published: raw boot logs, the full IMDS instance document (subscription id), package logs.
