# Azure Confidential VM probe: SEV-SNP behind the paravisor, the vTPM chain, and the MAA token

Companion to `../aws-vlek/` and `../gcp-cvm/`. Captured 11 September 2026 on `Standard_DC2as_v5`
(AMD Milan, SEV-SNP) in East US and West Europe, Ubuntu 24.04 CVM image. Intel TDX
(`DCesv5`) is not offered to this subscription in any commercial region (`az vm list-skus`
returns only a canary region), so the TDX case is recorded as unavailable rather than measured.

## Method

- `launch.sh snp <region>`: `az vm create --security-type ConfidentialVM`, vTPM and Secure Boot
  on, no inbound rule, boot diagnostics on, `probe-azure.sh` as cloud-init custom-data.
- `probe-azure.sh` captures:
  1. the HCL report from TPM NV index 0x01400001: 32-byte header, the SEV-SNP
     ATTESTATION_REPORT the paravisor obtained at boot, and the runtime-data JSON (the vTPM
     AK/EK public keys, VM configuration, `vmUniqueId`) whose SHA-256 is the report's
     REPORT_DATA;
  2. the VCEK and chain from Azure THIM (`/metadata/THIM/amd/certification`);
  3. a vTPM quote with the HCL attestation key (persistent handle 0x81000003) over our
     public nonce, so that freshness is proven through the chain chip → REPORT_DATA →
     runtime JSON → AK → nonce;
  4. the IMDS attested document (PKCS#7 signed by `metadata.azure.com`);
  5. a Microsoft Azure Attestation token from the shared regional provider, built exactly as
     Azure's own `cvm-attestation-tools` builds the request;
  6. kernel, `dmesg`, TPM handles, metadata.
- `collect.sh`: reads the boot-diagnostics serial log (returned by the CLI as one JSON string),
  decodes the archive, deletes the VM.
- `azure_verify.py`: independent verification: report signature with the THIM VCEK, THIM chain
  to ARK-Milan, `hwID == CHIP_ID`, THIM VCEK against a live KDS fetch (same key, re-issued
  certificate), REPORT_DATA binding of the runtime JSON, TPM quote signature with `HCLAkPub`
  and nonce check, MAA token signature against the provider's JWKS, PKCS#7 signer of the
  attested document. Output: `runs/summary.json`.

## Results

See `RESULTS.md`.
