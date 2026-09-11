# AWS Nitro: enclaves and NitroTPM

Two probes for the Nitro system, same discipline as `../aws-vlek/` (public nonce, raw artifacts, offline
verification, instance terminated only after a verified archive). Results in `RESULTS.md`.

- `probe-nitro.sh` + `launch.sh` + `collect.sh`: an enclave-enabled `m5.xlarge` builds a minimal enclave
  (python, cbor2, cryptography), the enclave asks the Nitro Security Module for three attestation documents
  through the NSM ioctl issued directly and hands them to the parent over vsock; the parent supplies the nonce
  over the same connection. `nitro_verify.py` verifies COSE_Sign1 (ES384) by hand, the chain to the AWS Nitro
  Enclaves root fetched from AWS, the nonce, the bound public key and the enclave's signature over the nonce,
  and lists every place-bearing string in the certificates. Output `runs/nitro-summary.json`.
- `probe-nitrotpm.sh` + `nitrotpm-ami.sh` + `nitrotpm-ekpub.sh`: no public AL2023 or Ubuntu image in the
  region carries `TpmSupport=v2.0`, so a copy is registered with it; the guest reads the TPM's properties and
  NV space, derives the EK and takes a quote with the nonce as qualifying data, while the operator asks the
  EC2 API for the instance's EK public key. `nitrotpm_verify.py` compares the two EKs, verifies the quote
  and checks the qualifying data. Output `runs/nitrotpm-summary.json`.

Not published: the instance identity document (account id), raw console captures, package logs, the
debug-mode enclave documents (PCRs zero).
