# Where a place can enter an attestation artifact: measured atlas

One question asked of every platform: for each signed artifact the platform produces, does any
byte say where the machine is, who put it there, and what class is that in RFC 9334 terms
(Evidence measured by the Attester, Endorsement asserted by a third party, Attestation Result
concluded by a Verifier). Everything marked *measured* was captured on real hardware by the
scripts in this repository, with a public nonce, and verified independently on the operator's
machine; the raw artifacts are in the per-platform `runs/` directories.

| platform and artifact | signer | locational content | class | status |
|---|---|---|---|---|
| AWS Nitro Enclaves attestation document | AWS Nitro Root G1 chain (in the COSE payload) | region only as a hostname label in the certificate CN; L/ST/C are the issuer's own address, byte-identical across regions | Endorsement | measured, 12 documents, us-east-2 / eu-west-1 (May 2026) |
| AWS EC2 SEV-SNP, shared tenancy | AMD VLEK ← SEV-VLEK-Milan ← ARK-Milan | none in the report (CHIP_ID zeroed); the VLEK certificate's CSP_ID is `cc-<region>.amazonaws.com`, keys differ per region. A VCEK signature cannot be requested: KEY_SEL 1 returns INVALID_KEY, the ABI's VCEK_DIS launch flag | Endorsement | measured, 6 instances, us-east-2a / eu-west-1a (11 Sep 2026), incl. KEY_SEL 0/1/2, the chained pair, channel binding and the identity-document binding → `aws-vlek/` |
| Google Cloud SEV-SNP | AMD VCEK ← ASK ← ARK | none; CHIP_ID present, hwID == CHIP_ID. No VLEK loaded: KEY_SEL 2 returns INVALID_KEY | (no geographic result) | measured, 10 (May) + 2 + 3 (11 Sep) VMs; 13 VCEK-signed VMs with Azure give 10 distinct CHIP_ID values → `gcp-cvm/` |
| Google Cloud Intel TDX | quote AK ← QE ← PCK ← Intel SGX Root CA | none | (no geographic result) | measured, 2 quotes, us-central1-a / europe-west4-a → `gcp-cvm/` |
| Google vTPM EK certificate | Google `EK/AK CA Intermediate` ← `EK/AK CA Root` | zone in the subject `L=` and in extension 1.3.6.1.4.1.11129.2.1.21 with project and instance | Endorsement | measured, 8 certificates → `gcp-cvm/` |
| Google Compute Engine identity token | `accounts.google.com` | `google.compute_engine.zone` | Endorsement | measured, 6 tokens → `gcp-cvm/` |
| Google Cloud Attestation token | Google attestation verifier | `submods.gce.zone` per documentation | Attestation Result | not obtained: verifier refused Ubuntu and COS VMs (three attempts, messages recorded) |
| Azure SEV-SNP (paravisor HCL report) | AMD VCEK (from Azure THIM) ← SEV-Milan ← ARK-Milan | none; CHIP_ID present, hwID == CHIP_ID; REPORT_DATA binds the runtime JSON, which names the VM, not the place | (no geographic result) | measured, 2 reports, East US / West Europe → `azure-cvm/` |
| Azure IMDS attested document | `metadata.azure.com` (PKCS#7) | none (vmId, subscription, sku) | Endorsement of identity | measured, 2 → `azure-cvm/` |
| Microsoft Azure Attestation token, SGX | regional MAA provider | region only as the issuer's address (`sharedeus2.eus2`, `sharedweu.weu`, `sharedeas.eas`) | Attestation Result | measured, 4 tokens (May 2026) |
| Microsoft Azure Attestation token, SEV-SNP | regional MAA provider (`sharedeus.eus`, `sharedweu.weu`) | region only as the issuer's address; the `x-ms-sevsnpvm-*` claims name the chip, measurement and policy, never a place | Attestation Result | measured, 2 tokens, East US / West Europe (11 Sep 2026) → `azure-cvm/runs/*-3/`, `*-2/` |
| Azure Intel TDX (DCesv5) | | | | not available to the subscription in any commercial region |
| bare-metal TPM 2.0 (EK certificate) | TPM vendor CA | none; operator inventory maps EK to a rack | Endorsement | specification only |
| Arm CCA realm / platform token | platform key | none (implementation and instance identifiers) | (no geographic result) | specification only; no public cloud offer |
| mobile device with trusted GNSS, RFC 9711 `location` claim | device attester | latitude/longitude from the sensor | Evidence | specification only (RFC 9711 §4.2.10) |
| network measurement (TRIP, latency, fibre timing) | the Verifier or its probes | distance or region inferred from timing | Verifier observation | proposal: register as a method with its class; worked example in `vectors-trip/` |

## Reading the table

- No hardware root of trust in any public cloud states a place. Every signed place is a
  provider statement: a certificate subject, a key-domain name, a token issuer's address.
- The same VM can yield geographic Attestation Results of different classes depending on
  which artifact a Verifier consumed. That is the case for the `basis` field.
- One guest cannot hold both AMD signatures on any of the three platforms: AWS shared tenancy
  disables the VCEK per guest (VCEK_DIS), Google and Azure load no VLEK. The chained pair
  (report B carrying SHA-512 of report A in REPORT_DATA) is verified as a construction and
  needs one launch bit from a provider, not a change to the ABI or to the draft.
- Freshness is provable on every measured platform, but through different chains: a nonce in
  REPORT_DATA (AWS, Google SEV-SNP), REPORTDATA (Google TDX), or a vTPM quote signed by an AK
  that the chip's report binds (Azure).
