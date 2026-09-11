# Results: AWS Nitro (11 September 2026)

Two artifacts from the Nitro system, captured with the same discipline as the SEV-SNP runs (public nonce,
raw files, verification on the operator's machine, instance terminated only after a verified archive).

## NitroTPM: what AWS's virtual TPM certifies

Two `m6a.xlarge` instances in `us-east-2a` from an Amazon Linux 2023 image registered with `TpmSupport=v2.0`
(no public AL2023 or Ubuntu image in the region carries the attribute; `nitrotpm-ami.sh` makes the copy).
Probe `probe-nitrotpm.sh`, verifier `nitrotpm_verify.py`, output `runs/nitrotpm-summary.json`.

| | i-0c9265f12ca6bc9d7 (16:26Z) | i-0d2c513e63ec85c64 (16:30Z) |
|---|---|---|
| TPM manufacturer / vendor string / firmware | `AMZN` / `NitroTPM` / 0x20191023 | same |
| EK certificate in NV (0x01c00002 RSA, 0x01c0000a ECC) | **none**; the TPM lists no NV index at all | none |
| EK public key from the EC2 API (`GetInstanceTpmEkPub`, DER, RSA-2048 and ECC P-384) | not requested | returned while the instance ran |
| API EK modulus == modulus of the EK the guest derived (`tpm2_createek`) | — | **true** |
| quote under a fresh AK, extraData = SHA-256 of the sentence, PCRs 0–7 | signature OK, extraData matches | signature OK, extraData matches |
| anything about place in the TPM's own artifacts | nothing (no certificate exists to carry it) | nothing |

What it settles. NitroTPM ships no endorsement certificate; the endorsement of the key is an API answer from
the EC2 control plane, that is, an AWS statement delivered over an authenticated API call to the account owner,
not a certificate a third party can check later. The instance's place (region, zone) is therefore not in any
TPM artifact; it is in the API's context (the region the call went to) and in the instance identity document.
In the atlas this is an Endorsement without a certificate: the Relying Party has to trust the account holder's
API session, or the account holder has to re-sign what the API said. Google's vTPM, by contrast, carries the
zone inside an EK certificate signed by Google's CA (`../gcp-cvm/RESULTS.md`).

## Nitro Enclaves: attestation document with a public nonce

Probe `probe-nitro.sh`: a minimal enclave (python, cbor2, cryptography) asks the Nitro Security Module for three
documents through the NSM ioctl issued directly (no library) and hands them to the parent over vsock; the parent
supplies the nonce over the same connection so that the enclave image does not depend on it. Verifier
`nitro_verify.py` (COSE_Sign1 ES384 with pycose, chain to the AWS Nitro Enclaves Root G1 fetched from AWS).

One `m5.xlarge` in `us-east-2a` (i-0b2d907210e5f2906, 16:48Z), enclave of 2 vCPU and 1 GiB. Three documents,
one public nonce (SHA-512 of the sentence), verified offline (`runs/nitro-summary.json`):

| | doc-nonce | doc-bound | doc-nonce-2 (3 s later) |
|---|---|---|---|
| COSE_Sign1, alg ES384 (-35), signature under the leaf certificate | OK | OK | OK |
| chain leaf ← instance CA ← zonal CA ← regional CA ← `aws.nitro-enclaves` root | OK | OK | OK |
| root certificate fetched from `aws-nitro-enclaves.amazonaws.com`, SHA-256 `641a0321…bb5b`, equal to the fingerprint AWS publishes on its "Verifying the root of trust" page | yes | yes | yes |
| nonce == SHA-512 of the sentence | yes | yes | yes |
| user_data / public_key | none | the string the enclave sent / the enclave's Ed25519 SPKI | none |
| Ed25519 signature over the nonce under that public key | — | verifies | — |
| PCR0 (real, not debug mode) | `04473d8c…` | same | same |
| module_id | `i-0b2d907210e5f2906-enc01a0916058586e5a` | same | same |
| place in the certificates | region only, as hostname labels: leaf `CN=<module>.us-east-2.aws`, instance CA `CN=i-….us-east-2.aws.nitro-enclaves`, zonal CA `CN=<hash>.zonal.us-east-2.aws.nitro-enclaves` (the zone itself is not named), regional CA `CN=<hash>.us-east-2.aws.nitro-enclaves`; `L=Seattle, ST=Washington` is Amazon's address on every certificate | same | same |

What it settles. The May corpus finding is now public and nonce-bound: the Nitro attestation document
names the region as a DNS-style label inside the certificate chain, never the availability zone, and the
`L`/`ST` fields are the issuer's corporate address. The signer is AWS's Nitro hypervisor infrastructure
(the chain is AWS's own PKI), so the class is Endorsement. The `public_key` field carries a key the enclave
generated and the enclave signs the nonce with it, so the session-binding construction of `PROTOCOLS.md`
(protocol 5) holds on Nitro as well; `user_data` is where an enclave would put the digest of a provider
statement (protocol 3), untested here because the enclave has no network to fetch one.

### Attempt log

16:25Z first instance: `nitro-cli build-enclave` failed with E51 (user-data runs without the package's
profile script, so `NITRO_CLI_BLOBS`/`NITRO_CLI_ARTIFACTS` were unset). 16:29Z second: the enclave ran but the
parent listener had died at import (`pip3` is not on Amazon Linux 2023; the CBOR module was dropped from the
parent, plain length-prefixed frames instead). 16:33Z third: the enclave exited at once; the console could
not be attached afterwards (E44), so a debug-mode run with `--attach-console` was added before the real run.
16:40Z fourth: the console showed `execvpe: python3: No such file or directory`: the enclave init has no PATH,
the image's CMD now uses `/usr/local/bin/python3`. 16:48Z fifth: documents received in the debug run
(PCRs zero, kept under `debug/`, not evidence) and in the real run (above). Every instance was terminated by
the collector after a verified archive; nothing is left running.

