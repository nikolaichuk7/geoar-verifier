# TACRA credential binding, measured on hardware

A worked example and a platform-capability matrix for draft-novak-rats-tacra-00 (Trustworthy
Acquisition of Credentials using Remote Attestation), contributed toward the RATS interim. It
answers the draft's open **CSR-to-Evidence binding** TODO (Sections 4.4, 5.2) with a concrete,
verifiable construction on real AMD SEV-SNP hardware, and it shows, from measurement, where the
"include CSKpub in Evidence" assumption holds and where it does not across the public clouds.

## Worked example: enrollment binding on SEV-SNP (12 September 2026)

Modelling the Credential Acquisition Interface (Section 4.4): the guest generates a credential
signing key (CSK, EC P-256) and a CSR, takes the Credential Authority's present-nonce freshness
handle (Section 2.1), and binds both into Evidence:

    REPORT_DATA = SHA-512(nonce || CSR_DER)          (SHA-512 is 64 bytes = the REPORT_DATA field)

then obtains a VCEK-signed SEV-SNP report. The Credential Authority (`tacra_verify.py`) recomputes
the binding and checks, before issuing for CSKpub:

| check | result |
|---|---|
| `REPORT_DATA == SHA-512(nonce ‖ CSR)` (binds this CSR and the CA nonce) | pass |
| report ECDSA-P384 signature under the VCEK | pass |
| VCEK chains to AMD `ARK-Milan` (fetched from the KDS) | pass |
| VCEK `hwID` == report `CHIP_ID` | pass |
| CSR self-signature (proof of possession of CSKpri) | pass |
| **CA may issue for CSKpub** | **yes** |

Run: Google SEV-SNP, `n2d-standard-2` (AMD Milan), chip `d29ed63f8755…`, CA nonce `c456ed0c…`,
credential key `SHA-256(CSKpub)=6a74610e…`. The credential private key never leaves the guest.
Files under `runs/`; machine-checked in `runs/<stamp>/tacra_verify.json`.

This gives the draft a concrete answer to "there MUST exist a binding between the CSR/CSKpub and
Evidence … TBD": put `SHA-512(freshness ‖ CSR)` in the attestation freshness field, and let the
Credential Authority recompute it. The same shape works for retrieval (Section 5.3): bind
`SHA-512(freshness ‖ CEKpub)`.

## Honest limit, and the fix (public references only)

This binds the CSR to a genuine TEE and to the CA's nonce. It does **not** bind the request to the
CA ↔ attester channel: a relay can still sit between the attester and the Credential Authority, as
the public analysis of public-key binders shows (ID-Crisis, ASIA CCS 2026; Intra-handshake.fail,
CVE-2026-33697; and RFC 9266). The remedy is to also fold a value derived from the session's shared
secret — the RFC 9266 TLS exporter of the CAS transport — into the freshness field:

    REPORT_DATA = SHA-512(exporter || CSR_DER)   (or exporter alongside the nonce)

## Platform matrix: can the Attester place CSKpub into Evidence, and what identity does it carry?

Measured in this repository (`aws-vlek/`, `azure-cvm/`, `gcp-cvm/`, `aws-nitro/`):

| platform | guest controls the freshness field? | identity the Evidence carries | TACRA binding path |
|---|---|---|---|
| Google SEV-SNP (VCEK) | yes — `REPORT_DATA` guest-chosen (this worked example) | per-chip `CHIP_ID` (VCEK `hwID` == `CHIP_ID`) | direct: CSKpub/CSR into `REPORT_DATA` |
| Google Intel TDX | yes — `REPORTDATA` guest-chosen | per-platform | direct |
| AWS Nitro Enclaves | yes — `user_data`/`nonce`/`public_key` in the attestation doc | PCRs (image); no per-machine chip id | direct: CSKpub as the doc's `public_key` |
| AWS NitroTPM / vTPM | yes — TPM quote `extraData` guest-chosen | per-instance AK/EK | indirect: via the TPM quote |
| AWS SEV-SNP, shared tenancy (VLEK) | yes — `REPORT_DATA` guest-chosen | **none per-machine**: `CHIP_ID` zeroed, shared VLEK; only `CSP_ID` = `cc-<region>.amazonaws.com` | direct, but the CA can bind only to the provider's key domain, not a machine |
| Azure SEV-SNP (paravisor) | **no** — `REPORT_DATA` is fixed at boot to `SHA-256(runtime JSON)`; the paravisor owns it | via the vTPM: runtime JSON carries `HCLAkPub`, an AK-signed TPM quote carries the nonce | indirect: CSKpub/CSR must be bound through the vTPM quote, not the SNP `REPORT_DATA` |

Consequence for the architecture (Section 4): the CAI's platform plug-ins must handle *who owns the
freshness field*. On Google and Nitro the CSKpub goes straight into the report; on Azure it has to
travel through the paravisor's vTPM; and on AWS shared SEV-SNP the Evidence cannot name the machine,
so a credential there rests on the provider, not on a chip. TACRA's "any workload, any platform"
holds only if the binding step is defined per these three shapes.

## Reproduce

`../gcp-cvm/probe-tacra.sh` is the guest probe (launch one Google SEV-SNP guest with a `ca-nonce`
metadata attribute and this as the startup script). `tacra_verify.py <run-dir>` is the Credential
Authority check against the AMD KDS. No private key leaves the guest; only public parts are shipped.
