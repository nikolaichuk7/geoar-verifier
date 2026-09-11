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
- `probe-keysel.sh`, `probe-dual.sh`, `probe-idbind.sh` (11 September): the same transport,
  no Rust build, the report requested through the `SNP_GET_REPORT` / `SNP_GET_EXT_REPORT`
  ioctls from twenty lines of Python. `probe-keysel.sh` asks for the report three times with
  KEY_SEL = 0, 1, 2 (firmware default, VCEK, VLEK). `probe-dual.sh` adds the chained pair
  (report B carries SHA-512 of report A in REPORT_DATA), a channel-binding report
  (REPORT_DATA = SHA-512(nonce || SPKI of an ephemeral Ed25519 key, the key signs the nonce)),
  and the certificate table the hypervisor supplies. `probe-idbind.sh` binds the EC2 instance
  identity document (region, availability zone, AWS PKCS#7 and RSA signatures) into
  REPORT_DATA. The archive is written to the serial console as indexed 76-character lines,
  three copies, with its SHA-256 in the header, because cloud-init and kernel lines land in
  the middle of a long console write (the 13:04Z capture was lost that way).
- `collect.sh`: reads the serial console with `get-console-output --latest`, reassembles the
  archive with `../tools/decode_console.py` (by line index across the copies, SHA-256
  checked), extracts it into `runs/<instance-id>/`, and terminates the instance only after
  a verified extraction.
- `dual_verify.py`: replays the 11 September runs: which certificate verifies each report
  (host table or KDS by CHIP_ID and TCB), chain to ARK-Milan, CSP_ID / hwID extensions,
  REPORT_DATA bindings of the chained pair and of the channel-binding report, the Ed25519
  signature, and the firmware status of every request. Output: `runs/dual-summary.json`.
  `idbind_verify.py` does the same for the identity-document run (`runs/idbind-summary.json`),
  fetching the region's document-signing certificates from the AWS documentation.
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
