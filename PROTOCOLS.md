# Five verification protocols for a geographic Attestation Result, measured

Companion to `ATLAS.md` (where a place can enter an artifact) and `LEDGER.md` (the record per
machine). Each protocol below is something a Verifier or an operator can run today against a
public cloud, using only the platform's own attestation interface; each is measured on real
hardware in this repository, and each says what it proves and what it does not. Terms are RFC 9334
(Evidence, Endorsement, Attestation Result). The AMD field names are from the SEV-SNP Firmware ABI
(document 56860, Rev. 1.58, May 2025: Section 3.7 for VLEK and VCEK_DIS, Section 7.3 and Table 22
for MSG_REPORT_REQ and KEY_SEL, Section 8.18 for SNP_LAUNCH_FINISH).

| # | protocol | question it answers | measured on | status |
|---|---|---|---|---|
| 1 | Machine record | which chip signed, and is it one I have seen | Google (11 VMs), Azure (4 VMs), AWS (6 instances) | `LEDGER.md`: 22 rows, 16 VCEK-signed boots on 15 VMs, 11 distinct chips, every signature verified |
| 2 | Re-attestation | is the workload still on the same chip | Google, one VM, ten reports across 3 minutes, then stop and start, ten more | verified 13:41–13:50Z: same chip across both boots, REPORT_ID changed at the relaunch |
| 3 | Bound platform statement | the provider's own statement about the place, joined to the chip's report | AWS (identity document), Google (EK certificate, identity token), Azure (native) | AWS verified 13:24Z; Google verified 13:42Z; Azure measured 11 Sep 01:00–01:30Z |
| 4 | Chained pair | one guest, both AMD keys | Google (mechanics), AWS (refused) | construction verified; no public platform lets a guest complete it today |
| 5 | Session binding | is this report about the channel I am talking over | Google (1 VM, TLS 1.3, direct and through a relay holding the guest's key); the key-only form also on AWS SEV-SNP, Google, Nitro | measured 17:58Z: the key binder accepts through the relay, the exporter binder rejects it |

## 1. Machine record (`tools/fingerprint_ledger.py`, output `LEDGER.md`, `ledger.json`)

**Steps.** Fresh nonce N (here: SHA-512 of a public sentence naming the run). Request a report
with REPORT_DATA = N. Read SIGNING_KEY from FLAGS. If VCEK: fetch the VCEK from AMD KDS by the
report's CHIP_ID and REPORTED_TCB, check hwID (OID 1.3.6.1.4.1.3704.1.4) equals CHIP_ID, verify the
ECDSA P-384 signature, verify the chain to ARK-Milan. If VLEK: take the VLEK the hypervisor supplies
with the extended report, verify the signature and the chain through SEV-VLEK-Milan, read CSP_ID
(OID 1.3.6.1.4.1.3704.1.5). Record: signing key, CHIP_ID, SPKI SHA-256 of the verifying
certificate, TCB, REPORT_ID, MEASUREMENT, time, nonce.

**What it proves.** That a genuine AMD firmware at the recorded TCB signed these bytes with the key
AMD certifies for that CHIP_ID (VCEK) or for that CSP key domain (VLEK), and that the report is
fresh for N. A CHIP_ID seen again is the same machine seen again, because the same KDS certificate
verifies both runs.

**What it does not prove.** Where the chip is. Nothing in the report or in the AMD certificates
names a place; the CSP_ID names a key domain the provider enrolled (`cc-us-east-2.amazonaws.com`).
Whether CHIP_ID is unique per die or per group is AMD's statement to make; from the Verifier's
side the key is bound one-to-one to the value.

**Measured.** 22 rows. Google and Azure: 15 VMs (16 boots), 11 distinct CHIP_ID values; VMs launched in
`us-central1-b` hours after earlier ones came back with CHIP_IDs seen before (same host reused), one
chip four times across thirteen hours and three VMs.
AWS shared tenancy: CHIP_ID all zeros in all six instances (MASK_CHIP_ID), the VLEK per region
(one SPKI in Ohio across four instances and two days, another in Ireland).

## 2. Re-attestation as a move detector (`gcp-cvm/probe-reattest.sh`, `gcp-cvm/reattest.sh`)

**Steps.** Repeat protocol 1 on a schedule with a fresh nonce each time, from inside the running
workload. Compare CHIP_ID and REPORT_ID with the previous record. Same CHIP_ID and same REPORT_ID:
same guest on the same chip. Same CHIP_ID, new REPORT_ID: the guest was relaunched on the same
chip. New CHIP_ID: the workload is on another machine, so any geographic Attestation Result issued
for the old record is stale.

**What it proves.** Continuity of the chip under the workload, at the sampling interval. The
firmware "generates a report ID for each guest that persists with the guest instance throughout
its lifetime" (56860, Section 7.3), so REPORT_ID distinguishes a relaunch from continuity.

**What it does not prove.** A move that is undone between two samples; and, again, the place.
Google Cloud states that SEV-SNP and TDX Confidential VMs are not live-migrated (maintenance policy
TERMINATE), so on Google a change of chip implies a stop and a restart, which the guest also sees
as a new REPORT_ID.

**Measured.** Google `us-central1-b`, one VM (`gcp-cvm/runs/rats-snp-us-central1-b-reattest`), 11
September. First boot, 13:41:27–13:44:27Z: ten reports, ten fresh nonces, one CHIP_ID (`f1cf2d6f…`),
one REPORT_ID (`08c80326…`), one MEASUREMENT. The VM was then stopped and started from the API.
Second boot, 13:46:54–13:49:54Z: ten reports, the same CHIP_ID, a new REPORT_ID (`aa4ef53d…`), the
same MEASUREMENT, a new kernel boot id. So the relaunch is visible to the Verifier (REPORT_ID) and
the chip continuity is visible too (CHIP_ID); the VM came back to the machine it had left. That
chip is the one the first Ubuntu VM and the `cos` VM of 00:51Z and 00:59Z also reported, so the
ledger now shows it four times across thirteen hours and three VMs.

## 3. Bound platform statement (`aws-vlek/probe-idbind.sh`, `gcp-cvm/probe-bind-gcp.sh`)

**Steps.** Obtain the provider's own signed statement about the VM: on AWS the EC2 instance identity
document (region, availability zone, instance id; PKCS#7 and RSA-2048 signatures by AWS); on Google
the vTPM EK certificate (zone in the subject and in extension 1.3.6.1.4.1.11129.2.1.21; signed by
Google's EK/AK CA) and the Compute Engine identity token (zone claim; signed by Google, JWKS).
Request a report with REPORT_DATA = SHA-512(N || SHA-256(statement)). The Verifier checks the
provider's signature on the statement, the AMD signature on the report, and the digest.

**What it proves.** Two independent signers about the same VM, joined in one firmware-signed
report: AMD certifies the key (and, for VLEK, the CSP key domain), the provider certifies the place
and the instance. The join proves that the guest held that statement when it asked for the report.

**What it does not prove.** That the statement is about this guest rather than a copied one; the
guest chooses what to hash. Both statements remain Endorsements; the Verifier's policy decides
whom to trust for the place. Azure does this natively: the paravisor writes SHA-256 of its runtime
JSON (vTPM keys, VM configuration) into REPORT_DATA before the guest sees the report, so on Azure
the binding is the platform's, not the guest's.

**Measured.** AWS us-east-2a, 11 September 13:24Z: PKCS#7 (DSA-SHA1 certificate) and RSA-2048
(SHA-256 certificate) both verify against the certificates AWS publishes for Ohio; REPORT_DATA
binding true; VLEK signature and chain OK; CSP_ID `cc-us-east-2.amazonaws.com` names the
document's region (`aws-vlek/runs/idbind-summary.json`). Google `us-central1-b`, 11 September 13:42Z (`gcp-cvm/runs/rats-snp-us-central1-b-bind`): three
reports, one nonce; all three verify under the VCEK that KDS issues for CHIP_ID `a2b2580a…` (hwID =
CHIP_ID, chain to ARK-Milan); r-ek binds the RSA EK certificate, which verifies under Google's `EK/AK CA
Intermediate` and carries `L=us-central1-b` in the subject and zone, project, instance id and instance name
in extension 1.3.6.1.4.1.11129.2.1.21; r-jwt binds the identity token, which verifies under Google's JWKS
and carries `zone: us-central1-b`; both digests match (`gcp-cvm/runs/bind-summary.json`). Azure: four
runs, REPORT_DATA = SHA-256(runtime JSON) || zeros in every report (`azure-cvm/RESULTS.md`).

## 4. Chained pair, one guest and both AMD keys (`aws-vlek/probe-dual.sh`, `dual_verify.py`)

**Steps.** Report A with KEY_SEL 2 (VLEK) and REPORT_DATA = N. Report B with KEY_SEL 1 (VCEK) and
REPORT_DATA = SHA-512 of A's 1184 bytes. Verify both as in protocol 1; check B.REPORT_DATA and that
both carry the same REPORT_ID.

**What it proves.** The CSP identity (VLEK, CSP_ID) and the chip identity (VCEK, hwID = CHIP_ID) for
the same guest at the same moment, joined by a digest the firmware signed, without any new field.

**What it does not prove.** Anything, on the public platforms measured, because one of the two
requests is refused. The ABI lists three conditions for INVALID_KEY on a report request: KEY_SEL 1
with VcekDis set, KEY_SEL 2 without a VLEK, KEY_SEL 0 with both. AWS shared tenancy refuses
KEY_SEL 1 (VcekDis, the VCEK_DIS flag of SNP_LAUNCH_FINISH); Google refuses KEY_SEL 2 (no VLEK
loaded); Azure's paravisor chooses the key. The construction needs a provider to load a VLEK and
leave VCEK_DIS clear, one bit at launch.

**Measured.** Google `us-central1-b`, three VMs, 13:16Z: the mechanics with the VCEK standing in for
both keys, B.REPORT_DATA = SHA-512(A), same REPORT_ID, both signatures verify. AWS `us-east-2a` and
`eu-west-1a`, 13:16Z: A (VLEK) OK, B refused with status 27h. AWS documents VCEK on Dedicated Hosts;
not measured (Dedicated Host limit 0 on the account).

## 5. Session binding against diversion (`probe-dual.sh`, report `cb`)

**Steps.** Put a value that only the two ends of the session can derive into the freshness field of
the Evidence: in TLS the exporter value of RFC 9266, which is derived from the handshake's shared
secret. Request a report with REPORT_DATA = SHA-512(nonce || that value). The Verifier recomputes the
value from its side of the session and checks the report.

**What the demo does, and its limit.** The runs in this repository bind a public key: an ephemeral
Ed25519 key generated in the guest, REPORT_DATA = SHA-512(N || SubjectPublicKeyInfo), and the key
signs N. That shows the mechanism end to end, but a public key is not a session: Sardar, Moustafa and
Aura (ASIA CCS 2026) analyse this binder among others and show that binding Evidence to a key alone
does not correlate it with the TLS session (their goals G-C1a..c fail); the binding that does is one
derived from the shared secret (their Sol. 5: an exporter-like value in the signed data). Usama Sardar
made this point on the RATS list on 11 September. So: the field and the construction are right, the
value to put there must come from the session's shared secret, not from a key.

**What it proves, once bound to the shared secret.** That the peer the Relying Party is talking to is
the guest that obtained the report, so a genuine report from a machine in the attested place cannot be
relayed by a peer elsewhere (the diversion of ID-Crisis, Section 8). This is the binding a geographic
Attestation Result should carry into the Relying Party's session.

**What it does not prove.** The place; and nothing about the chip beyond protocol 1.

**Measured.** AWS `us-east-2a`, `eu-west-1a`, Google `us-central1-b` (three VMs), 13:16Z: REPORT_DATA
binding true and Ed25519 signature over N verified in all five (`runs/dual-summary.json`). AWS Nitro
Enclaves, 16:48Z: the document's `public_key` field carries the enclave's Ed25519 SPKI and the enclave
signs the nonce (`aws-nitro/runs/nitro-summary.json`).

**Measured, both binders side by side** (`gcp-cvm/probe-exporter.sh`, `tools/exporter_client.py`,
`gcp-cvm/exporter/runs/`). One Google SEV-SNP VM runs a TLS 1.3 server; for each client session it derives
the RFC 9266 exporter value of that session and requests two reports with one nonce: REPORT_DATA =
SHA-512(nonce || exporter) and REPORT_DATA = SHA-512(nonce || SPKI of the server's TLS key), and signs the
nonce with the TLS key. The client derives its own exporter and checks both. The relay is a TLS server on
the operator's machine that holds the guest's TLS key (the leaked-key attacker of the binder analysis),
terminates the client's session, opens its own session to the guest and forwards the nonce and the blob.

| check at the client | direct to the guest | through the relay |
|---|---|---|
| both SNP reports verify under the KDS VCEK for the chip (`a2b2580a…`), same REPORT_ID | yes | yes (genuine reports, genuine chip) |
| key binder: REPORT_DATA = SHA-512(nonce ‖ SPKI), signature over the nonce, TLS peer key = attested SPKI | accepts | **accepts**: every check passes although the client is talking to the relay |
| exporter binder: REPORT_DATA = SHA-512(nonce ‖ exporter derived by the client) | accepts (exporters equal) | **rejects**: client exporter `72b395fe…`, guest-side exporter `361367e7…` |

So the two reports are equally genuine and the chip is the same; only the exporter binder tells the client
that the session it is in is not the session the guest attested. Post-handshake binding of this kind is the
direction Sardar's work recommends (exported authenticators, RFC 9261); the earlier key-only demo stays in
the repository as the negative case.

## What the five together give a Verifier

A record per machine (1), a way to notice when the workload leaves it (2), the provider's place
statement joined to that record with the signer named (3), and a channel binding for the Relying
Party (5). Protocol 4 is what the ABI already allows and no provider yet exposes. None of the five
turns a provider statement into Evidence: the place still comes from an Endorsement, and a
geographic Attestation Result should say so in its `basis`.
