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
