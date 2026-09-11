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

The attestation verifier (`gotpm token`, go-tpm-tools at commit ee8ec5b) refused every VM,
Ubuntu and Container-Optimized OS alike: TDX "Unable to verify attestation: no GRUB
measurements found", SEV-SNP "invalid request: unexpected_snp_attestation". Three attempts
(`runs/*-cos*`), the last with a privileged container so that the tool could read the TCG
event log and the TEE devices; the full `gotpm attest` output (TPM quote, event log, EK
certificate, TEE report) is kept per run as `gotpm-attestation.bin`, only the server-side
verification step is refused. Google documents the token for Confidential Space workloads,
which is a different launcher; that path was not exercised here. So for Google the two
signed zone statements in hand are the EK certificate and the identity token, both Endorsements.

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

## 11 September, 13:16Z: key selection, the chained pair, channel binding (three VMs, one zone)

Three Ubuntu 24.04 SEV-SNP VMs launched within one minute in `us-central1-b` with
`probe-dual.sh` (the same script as `../aws-vlek/probe-dual.sh`): the report requested three
times with KEY_SEL = 0, 1, 2, then the chained pair, the channel-binding report and the
certificate table from the hypervisor. Archives reassembled from the serial console by line
index and checked against the SHA-256 the VM printed; VMs deleted only after that check.

| | dual4 | dual5 | dual6 |
|---|---|---|---|
| KEY_SEL 0 (default) | **VCEK**, ok | VCEK, ok | VCEK, ok |
| KEY_SEL 1 (VCEK) | VCEK, ok | VCEK, ok | VCEK, ok |
| KEY_SEL 2 (VLEK) | **status 0x27 INVALID_KEY** | 0x27 | 0x27 |
| chained pair: B.REPORT_DATA == SHA-512(A), same REPORT_ID, both signatures verify | yes | yes | yes |
| channel binding: REPORT_DATA == SHA-512(nonce ‖ SPKI), Ed25519 signature over nonce | yes | yes | yes |
| certificate table from the hypervisor | VCEK + ASK (SEV-Milan) + ARK-Milan | same | same |
| report signatures verified with | the hypervisor's VCEK; chain to ARK-Milan OK | same | same |
| VCEK hwID == CHIP_ID | yes | yes | yes |
| CHIP_ID (first 16 hex) | 24d9104938ca35bd | da7f959f9936e0f8 | 28e9aeb5bfc75726 |

### What this settles

1. **Google loads no VLEK.** KEY_SEL 2 returns INVALID_KEY, the ABI's one condition for that
   value (56860 Rev. 1.58, Section 7.3); KEY_SEL 1 succeeds, so VcekDis is clear. The
   mirror image of AWS shared tenancy (`../aws-vlek/RESULTS.md`).
2. **The chained-pair construction is sound.** With the VCEK standing in for both keys, report
   B carries the SHA-512 of report A in REPORT_DATA, the firmware signs it, and a verifier can
   follow the digest from B to A. Where a provider exposes both keys the same two requests
   join a CSP identity (VLEK, CSP_ID) and a chip identity (VCEK, hwID = CHIP_ID).
3. **CHIP_ID across every VCEK-signed run so far: 13 VMs (9 Google, 4 Azure), 10 distinct
   values.** The three repeats are all `us-central1-b`: `dual5` and `dual6` returned the values
   of `cos2` and `cos3` (launched hours earlier), and the first Ubuntu VM and `cos` share a
   value. Three VMs launched in the same minute landed on three different values. In every
   case the report verifies under the certificate KDS issues for that CHIP_ID. Whether the
   name covers one die or a group is AMD's to say; the data shows a stable per-machine value
   that fresh VMs come back to.

## 11 September, 13:42Z: the provider's statement bound into the chip's report (protocol 3)

One VM in `us-central1-b` (`runs/rats-snp-us-central1-b-bind`), `probe-bind-gcp.sh`. Three
SEV-SNP reports with one public nonce N: `r0` with REPORT_DATA = N, `r-ek` with REPORT_DATA =
SHA-512(N ‖ SHA-256 of the vTPM RSA EK certificate), `r-jwt` with REPORT_DATA = SHA-512(N ‖
SHA-256 of the Compute Engine identity token). Verified offline (`bind_verify.py`,
`runs/bind-summary.json`):

| check | result |
|---|---|
| reports signed by | VCEK, CHIP_ID `a2b2580a…` (an eleventh distinct chip), same REPORT_ID in all three |
| KDS VCEK for CHIP_ID and TCB verifies all three; hwID == CHIP_ID; chain to ARK-Milan | yes |
| `r0` REPORT_DATA == N | yes |
| `r-ek` REPORT_DATA == SHA-512(N ‖ SHA-256(EK cert)) | yes |
| EK certificate signed by Google `EK/AK CA Intermediate` (fetched via AIA) | yes |
| EK subject / extension 1.3.6.1.4.1.11129.2.1.21 | `L=us-central1-b`; zone us-central1-b, project rats-probe, instance id and name |
| `r-jwt` REPORT_DATA == SHA-512(N ‖ SHA-256(identity token)) | yes |
| identity token signed by Google (JWKS via OpenID discovery), `zone` claim | yes; `us-central1-b` |
| certificate table from the hypervisor | VCEK + ASK + ARK |

What it settles: Google's two signed statements about the place (a CA statement in the EK
certificate, an identity-provider statement in the token) can be joined to the chip's report the
same way AWS's identity document was on `aws-vlek` and the way Azure's paravisor does natively.
The join proves that this guest held those statements when it asked for the report; the
statements remain Endorsements by Google, and the Verifier decides whom to trust for the place.

## 11 September, 13:41–13:50Z: re-attestation across a stop and start (protocol 2)

One VM in `us-central1-b` (`runs/rats-snp-us-central1-b-reattest`), `probe-reattest.sh` at every
boot: ten SEV-SNP reports twenty seconds apart, each with a fresh nonce naming the boot and the
sample. `reattest.sh` waited for the first boot's archive, stopped and started the VM, waited for
the second boot's archive, and deleted the VM only then.

| | boot 1 (13:41:27–13:44:27Z) | boot 2 (13:46:54–13:49:54Z) |
|---|---|---|
| samples with REPORT_DATA == nonce | 10 / 10 | 10 / 10 |
| CHIP_ID | `f1cf2d6f…` | `f1cf2d6f…` (same) |
| REPORT_ID | `08c80326…` (one value in all ten) | `aa4ef53d…` (new) |
| MEASUREMENT | `0e017d2f…` | `0e017d2f…` (same) |
| REPORTED_TCB | 4.0.29.222 | 4.0.29.222 |
| kernel boot id | 7c67fe3b… | 030be523… |
| GCE instance id | same | same |

What it settles: within one guest lifetime REPORT_ID is constant across reports (as the ABI
promises) and CHIP_ID is constant; across a stop and start REPORT_ID changes and CHIP_ID may or
may not, here it did not, the VM returned to the chip it had left. A Verifier that keeps the
ledger sees both facts without any help from the provider. This chip (`f1cf2d6f…`) is the one the
first Ubuntu VM (00:51Z) and the `cos` VM (00:59Z) reported: four sightings, three VMs, thirteen
hours.

## 11 September, 17:58Z: session binding, two binders through a relay (protocol 5, measured)

Usama Sardar's point on the list (17:17Z): binding a report to a public key is binder #6 of ID-Crisis and
does not correlate the Evidence with the TLS session. Measured on one VM (`rats-snp-us-central1-b-exporter2`,
`probe-exporter.sh`) with the client and a leaked-key relay on the operator's machine (`tools/exporter_client.py`):

| | direct | through the relay holding the guest's TLS key |
|---|---|---|
| TLS | 1.3 | 1.3 on both legs |
| exporter (RFC 9266, empty context, 32 bytes), client vs guest | equal | different (`72b395fe…` vs `361367e7…`) |
| key binder (REPORT_DATA = SHA-512(nonce ‖ SPKI), signature over nonce, peer key = SPKI) | accepts | **accepts** |
| exporter binder (REPORT_DATA = SHA-512(nonce ‖ client's exporter)) | accepts | **rejects** |
| both reports under the KDS VCEK (chip `a2b2580a…`), same REPORT_ID | OK | OK |

What it settles: with the key leaked, the key binder is blind to the relay; the exporter binder is not. The
draft's Security Considerations text was changed the same afternoon to require a binding derived from the
session's shared secret. Files: `exporter/runs/direct.json`, `relayed.json`, `relay.log`, the reports and blobs;
the guest's own session log arrives with its archive. The TLS key pair is generated per run on the operator's
machine and is not published.
