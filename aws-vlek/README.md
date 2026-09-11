# AWS EC2 SEV-SNP probe: the VLEK-signed case

Companion to the geographic-results discussion on rats@ietf.org (September 2026). The ten
Google Cloud SEV-SNP reports in the earlier runs are all VCEK-signed. AWS documents that
SEV-SNP instances on shared tenancy are signed with a Versioned Loaded Endorsement Key (VLEK)
"issued by AMD for AWS" (Dedicated Hosts use the VCEK). This directory captures that case on
real hardware so that the two signing modes can be compared byte for byte.

## Method

- `launch.sh`: one `m6a.large` per availability zone, `--cpu-options AmdSevSnp=enabled`,
  Amazon Linux 2023 with the 6.1 kernel, default VPC, no key pair, no inbound rule, no IAM
  role. The instance talks out only (dnf mirrors, GitHub, `kdsintf.amd.com`).
- `probe.sh` (user-data, runs once as root at first boot): builds `snpguest`, the utility AWS
  documents for this procedure; requests the report with a nonce that is **not random** but
  SHA-512 of a public sentence naming the mailing-list messages being answered, the instance
  id, the zone and the timestamp (`nonce-sentence.txt`, `nonce.hex`); dumps the certificate
  table the hypervisor supplies with the extended report (`certs/`); fetches the VLEK and VCEK
  chains from AMD KDS; runs `openssl verify` and `snpguest verify`; records kernel, `dmesg`,
  `/dev/sev-guest`, CPU flags and the EC2 instance-identity document; takes a second report
  seconds later with the same nonce; packs everything and writes it base64-encoded to the
  serial console between two markers.
- `collect.sh`: reads the serial console with `get-console-output --latest`, decodes the
  archive into `runs/<instance-id>/`, terminates the instance.
- `vlek_verify.py`: an independent check on the operator's machine, without `snpguest`:
  parses the 1184-byte report at the ABI offsets, checks REPORT_DATA against the public
  sentence, verifies the ECDSA P-384 signature with the leaf certificate, verifies the leaf
  against the KDS chain (RSA-PSS), lists the AMD extensions of the leaf (hwID present?
  CSP_ID present?), and compares leaf public keys across zones and regions.

Anyone with an AWS account can repeat the run with the three scripts; nothing in them
depends on this account.

## Boot note

The AL2023 `kernel-default` image of 2026-09-09 (kernel 6.18.44) shut itself down within
seconds of the kernel starting, on all three first-attempt instances, with EC2 reporting
`Client.InstanceInitiatedShutdown`. The same image with the 6.1 kernel (6.1.182) boots and
initialises the `sev-guest` driver (`vmpck_id 0`). A control instance on the 6.18 image
without any user-data (i-020620a3b55b8acdc, us-east-2b, 00:14Z) shut itself down the same
way, so the shutdown is a property of that image under SEV-SNP, not of the probe.

## Results

See `RESULTS.md` (written from `runs/summary.json` after the run).
