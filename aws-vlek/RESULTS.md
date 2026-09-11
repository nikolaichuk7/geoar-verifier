# Results: AWS EC2 SEV-SNP, shared tenancy, VLEK-signed (11 September 2026)

Two fresh captures, one per region, on `m6a.large` with `AmdSevSnp=enabled`, Amazon Linux
2023 kernel 6.1.182, report version 5, firmware 1.58.1 (current = committed). Both archives
passed the `sha256sums.txt` written on the instance (6/6 files). Instances were terminated
after collection; nothing is left running.

| | us-east-2a (Ohio) | eu-west-1a (Ireland) |
|---|---|---|
| instance | i-0d7bec270b4f73618 | i-0bf334666a8c4868c |
| captured | 2026-09-11 00:12:14Z | 2026-09-11 00:12:18Z |
| `dmesg` | Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP; sev-guest driver, vmpck_id 0 | same |
| flags word 0x48 | SIGNING_KEY = **VLEK**, MASK_CHIP_KEY = 0, AUTHOR_KEY_EN = 0 | same |
| CHIP_ID (0x1A0) | **all zeros** | **all zeros** |
| HOST_DATA (0xC0) | all zeros | all zeros |
| REPORT_DATA (0x50) | = SHA-512 of `nonce-sentence.txt` | = SHA-512 of `nonce-sentence.txt` |
| report signature (ECDSA P-384, our script) | OK | OK |
| `snpguest verify attestation` | "VEK signed the Attestation Report!" + 4 TCB matches | same |
| VLEK leaf subject / issuer | CN=SEV-VLEK / CN=SEV-VLEK-Milan (AMD) | same |
| VLEK leaf **CSP_ID** (OID 1.3.6.1.4.1.3704.1.5) | `CN=cc-us-east-2.amazonaws.com` | `CN=cc-eu-west-1.amazonaws.com` |
| VLEK leaf hwID (OID …3704.1.4) | absent | absent |
| VLEK public key (SPKI SHA-256, first 16 hex) | 5330c95b9cd4976c | 6f718ce827693226 |
| leaf notBefore | 2026-03-09 19:30:05Z | 2026-03-09 18:45:17Z |
| chain (our script, RSA-PSS) | leaf ← SEV-VLEK-Milan ← ARK-Milan, all OK | same |
| `openssl verify -CAfile kds-vlek-cert_chain.pem` | OK | OK |
| second report, same nonce, 2 s later | no field moved | no field moved |
| VLEK leaf serial number | 0 (RFC 5280 requires a positive serial; a quirk of AMD's VLEK issuance, noted so that nobody mistakes it for tampering) | 0 |
| certificate table from the hypervisor | `vlek.pem` only (no ASK/ARK; `snpguest verify certs` therefore reports "ark not found"; the chain was fetched from KDS instead) | same |

## What this settles

1. **AWS signs shared-tenancy SEV-SNP reports with a VLEK and zeroes CHIP_ID.** The
   MASK_CHIP_KEY report bit is 0; the zeroing is the platform's MaskChipId setting, which the
   report does not expose. The VLEK certificate carries no hwID. So under VLEK the artifact
   identifies neither the chip nor the host.
2. **The VLEK is scoped per region, and the region name is inside the AMD-issued
   certificate.** CSP_ID differs between Ohio and Ireland and the public keys differ. This
   is the one signed statement about place in an AWS SEV-SNP artifact, and it is a statement
   by AMD about the key domain AWS enrolled, with AWS choosing region-scoped domains. Nothing
   was measured by the chip. In RFC 9334 terms it is an Endorsement.
3. **Same wire format, different basis.** A VCEK-signed Google report (ten earlier captures:
   CHIP_ID present, four distinct values, no locational input at all) and a VLEK-signed AWS
   report are both "SEV-SNP" to a Relying Party. Only a field like `basis` in the geographic
   Attestation Result tells them apart.
4. **Freshness is checkable by anyone.** REPORT_DATA is SHA-512 of a public sentence naming
   the mailing-list messages answered, the instance id and the timestamp.

## Files per run (`runs/<instance-id>/<stamp>/`)

`report.bin` / `report.hex`, `report-2.bin` / `.hex`, `request-file.bin` / `.hex` (the nonce),
`nonce-sentence.txt`, `nonce.hex`, `certs/vlek.pem`, `kds-vlek-cert_chain.pem`,
`kds-vcek-cert_chain.pem`, `certs-summary.txt`, `report-display.txt`, `openssl-verify-vlek.txt`,
`verify-attestation.txt`, `verify-certs.txt`, `metadata.txt`, `kernel.txt`, `dmesg-sev.txt`,
`dev-sev-guest.txt`, `snpguest-version.txt`, `snpguest-commit.txt`, `sha256sums.txt`.
Not published: the EC2 instance-identity document (carries the account id), package and
build logs, raw console captures. `runs/summary.json` is the output of `vlek_verify.py`.

## Attempt log

00:06Z three `kernel-default` (6.18.44) instances shut themselves down within seconds of the
kernel starting (`Client.InstanceInitiatedShutdown`); 00:14Z a 6.18 control without user-data
did the same; 00:11Z two 6.1 instances booted, ran the probe and reported by 00:20Z.

## 11 September, 12:57–13:25Z: key selection, the chained pair, channel binding, identity-document binding

Answering Muhammad Usama Sardar's question of 11 September 10:31Z ("if I need both VCEK and
VLEK together, can I do that?"). Four fresh `m6a.large` instances on shared tenancy, Amazon
Linux 2023 kernel 6.1, no Rust build: the report is requested through the `SNP_GET_REPORT` /
`SNP_GET_EXT_REPORT` ioctls from Python. Every archive was reassembled from the serial console
by line index and checked against the SHA-256 the instance printed; every instance was
terminated only after that check. Nothing is left running.

| | us-east-2a 12:57Z | us-east-2a 13:16Z | eu-west-1a 13:16Z | us-east-2a 13:24Z |
|---|---|---|---|---|
| instance | i-036d8dbd13f29cba2 | i-02587934b18bc3016 | i-03dcf507880e1961e | i-0603037ab5b36aada |
| probe | `probe-keysel.sh` | `probe-dual.sh` | `probe-dual.sh` | `probe-idbind.sh` |
| KEY_SEL 0 (firmware default) | **VLEK**, ok | **VLEK**, ok | **VLEK**, ok | VLEK, ok |
| KEY_SEL 1 (VCEK) | **status 0x27 INVALID_KEY** | **0x27** | **0x27** | — |
| KEY_SEL 2 (VLEK) | VLEK, ok | VLEK, ok | VLEK, ok | — |
| chained pair A (KEY_SEL 2) → B (KEY_SEL 1, REPORT_DATA = SHA-512(A)) | — | A ok, **B refused 0x27** | A ok, **B refused 0x27** | — |
| channel binding, REPORT_DATA = SHA-512(nonce ‖ SPKI), Ed25519 signature over nonce | — | both verify | both verify | — |
| certificate table from the hypervisor (extended report, 16 KiB buffer) | `vlek.pem` via snpguest | VLEK only | VLEK only | VLEK only |
| report signature / chain to ARK-Milan via SEV-VLEK-Milan | OK / OK | OK / OK | OK / OK | OK / OK |
| CSP_ID in the VLEK certificate | cc-us-east-2 | cc-us-east-2 | cc-eu-west-1 | cc-us-east-2 |
| CHIP_ID | zeros | zeros | zeros | zeros |
| MASK_CHIP_KEY bit in FLAGS | 0 | 0 | 0 | 0 |

Identity-document binding (fourth column): REPORT_DATA = SHA-512(nonce ‖ SHA-256 of the EC2
instance identity document). The document (region us-east-2, availability zone us-east-2a,
instance id) verifies under AWS's PKCS#7 signature (DSA-SHA1 certificate) and under the
detached RSA-2048 signature (SHA-256 certificate), both certificates taken from the AWS
documentation page for Ohio; the report verifies under the VLEK whose CSP_ID names the same
region. The binding proves that the guest held the document when it asked for the report,
nothing more. The document itself is not published (it carries the account id);
`runs/idbind-summary.json` records the checks and the document's SHA-256.

### What this settles

1. **On AWS shared tenancy a guest cannot obtain a VCEK signature.** The ABI (56860 Rev. 1.58,
   Section 7.3, the actions under Table 22) lists exactly three conditions for INVALID_KEY on
   a report request: KEY_SEL 1 with VcekDis set; KEY_SEL 2 with no VLEK loaded; KEY_SEL 0
   with both. KEY_SEL 0 and 2 succeed, so a VLEK is loaded; KEY_SEL 1 fails, so VcekDis is
   set for the guest, the VCEK_DIS flag of SNP_LAUNCH_FINISH (Section 8.18) that Section 3.7
   describes as "the hypervisor can restrict guests to use only the VLEK". The guest cannot
   read the flag; this is the only rule that produces the status, and MASK_CHIP_KEY is 0.
2. **The chip is hidden on both paths.** MASK_CHIP_ID zeroes CHIP_ID and VCEK_DIS removes the
   per-chip key, so no AWS shared-tenancy artifact names the chip. The one signed statement
   about place remains AMD's CSP_ID in the VLEK certificate, a region-scoped name AWS chose.
3. **The chained pair is a one-bit ask to the provider, not a change to the ABI.** The
   construction works wherever both keys are usable (mechanics verified on Google with the
   VCEK standing in for both, see `../gcp-cvm/RESULTS.md`); on AWS report B is refused.
4. **Two signers about place can already be joined in one report:** AMD's CSP_ID (region) and
   AWS's signed identity document (availability zone), bound through REPORT_DATA. Both stay
   Endorsements in RFC 9334 terms.

Files per run add `dual-results.json` / `keysel-results.json` / `idbind-results.json`
(firmware status of every request), `report-k0/k1/k2/chA/chB/cb.bin` or `report-idbind.bin`,
`cert-VLEK.bin` (from the hypervisor's table), `eph-pub.der`, `eph-sig.bin`, `certs-summary.txt`,
`sha256sums.txt`. `runs/dual-summary.json` and `runs/idbind-summary.json` are the verifier outputs.

### Attempt log

13:04Z the first `probe-dual.sh` instance (i-07d86beca7f85f13f) printed its archive as one long
line; cloud-init lines landed inside it and the capture could not be decoded (the collector of
that hour terminated the instance anyway; it now terminates only after a verified extraction).
The 13:16Z runs use indexed 76-character lines, three copies, SHA-256 in the header. The same
run also showed that `SNP_GET_EXT_REPORT` rejects a 32 KiB certificate buffer with EINVAL
(the driver caps it at 16 KiB, page-aligned); 16 KiB works. A Dedicated Host (the VCEK case AWS
documents) could not be allocated: the account's Dedicated Host limit is 0.
