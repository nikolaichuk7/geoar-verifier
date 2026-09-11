# Google Cloud Confidential VM probe: SEV-SNP (VCEK) and Intel TDX, with the vTPM and token layers

Companion to `../aws-vlek/`. Same question, same discipline: for each signed artifact a
Confidential VM can produce, where could a place enter, who put it there, and what class is
that in RFC 9334 terms. Captured 11 September 2026 in `us-central1` and `europe-west4`.

## Method

- `launch.sh snp|tdx <zone>`: one Confidential VM per zone, Ubuntu 24.04, Shielded VM options
  on, `cloud-platform` scope, `probe-gcp.sh` as the startup script. SEV-SNP on
  `n2d-standard-2` (AMD Milan), TDX on `c3-standard-4`. No SSH, no inbound rule.
- `probe-gcp.sh` captures, with a public nonce (SHA-512 of a sentence naming the list
  messages, the instance and the timestamp):
  1. the raw hardware report: SEV-SNP through the `SNP_GET_REPORT` ioctl on `/dev/sev-guest`,
     issued by 20 lines of Python with no third-party code, and again through configfs-tsm;
     TDX quote through configfs-tsm (`/sys/kernel/config/tsm/report`);
  2. the vTPM endorsement-key certificates (RSA and ECC) from TPM NV, issued by Google's
     `EK/AK CA Intermediate`;
  3. the Compute Engine identity token (JWT signed by `accounts.google.com`);
  4. the Google Cloud Attestation token (`gotpm token`, built from go-tpm-tools in-tree) where
     the build succeeded (second pass);
  5. kernel, `dmesg`, devices, metadata.
- `collect.sh`: reads the serial console with `get-serial-port-output`, decodes the archive,
  deletes the VM.
- `gcp_verify.py`: independent verification on the operator's machine: SEV-SNP signature and
  VCEK chain fetched live from AMD KDS, `hwID == CHIP_ID` check; TDX quote signature with the
  embedded attestation key, QE report binding and signature, PCK chain to Intel's published
  root; EK certificate signature via AIA and decoding of Google's instance extension
  (OID 1.3.6.1.4.1.11129.2.1.21); JWT signatures against the issuer's JWKS via OpenID
  discovery. Output: `runs/summary.json`.

## Results

See `RESULTS.md`.
