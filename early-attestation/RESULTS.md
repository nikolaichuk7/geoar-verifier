# Relaying the Section 5.1.1 attestation binder, measured on SEV-SNP

11 September 2026. This directory measures the attestation binder of
draft-fossati-seat-early-attestation-06, Section 5.1.1, on real AMD SEV-SNP hardware, and shows
that it does not bind Evidence to the endpoint once the server's TLS identity key is available to
an attacker. This is the experiment Muhammad Usama Sardar suggested (LinkedIn, 11 Sep): put the
5.1.1 binder value into REPORT_DATA, leak the private key, and show the binder leads to a relay.
It reproduces, on hardware, the class of attack in *Intra-handshake.fail* (CVE-2026-33697, ESORICS
2026) against binding mechanisms that contain the server public key.

## The binder (Section 5.1.1, verbatim)

    attest_base     = HKDF-Expand-Label(0, "attestation base",
                                        Hash(ClientHello...ServerHello), Hash.length)
    s_attest_binder = HKDF-Expand-Label(attest_base, "attestation",
                                        Hash(TLS_Server_Public_Key), Hash.length)

`TLS_Server_Public_Key` is the DER-encoded SubjectPublicKeyInfo of the server's end-entity
certificate; `Hash` is the cipher-suite hash. The Section 5.1.2 client recomputes `s_attest_binder`
from the transcript it observed and the server key it saw, and accepts iff that value equals the
one carried in the signed Evidence and the Evidence appraises. On SEV-SNP the carried value is the
guest-chosen `REPORT_DATA` (64 bytes); we place the binder left-justified, zero-padded.

## Setup

Two SEV-SNP guests, Ubuntu 24.04, `n2d-standard-2` (AMD Milan), no SSH, results read from the
serial console. Both guests were launched with **the same** server TLS identity key (TIK) injected
by metadata: that shared key is the leaked key of the attacker in *Intra-handshake.fail* Section
7.1.4 and in the draft's own Section 5.2. Each guest runs a **real TLS 1.3 handshake in memory**
(`ssl.MemoryBIO`, TLS_AES_256_GCM_SHA384), captures the exact `ClientHello...ServerHello`
transcript, derives `s_attest_binder`, and requests a VCEK-signed report (`KEY_SEL 1`) with
`REPORT_DATA = s_attest_binder || 0`. The VCEK gives each report the signing chip's real `CHIP_ID`.

| role | region | instance | chip (`CHIP_ID`, first 16) |
|---|---|---|---|
| server S | us-central1-b (Iowa) | rats-early-server-uscentral1b | `0b0b368a140f008e` |
| attacker A | europe-west4-a (Netherlands) | rats-early-attacker-euw4a | `f72da6d73024ad54` |

Both reports carry the identical server key: `SHA-256(SPKI) = 89747f6e831c28cd…` on both. The two
transcripts differ (each guest ran its own handshake): `SHA-256 = 595f7c38…` (S), `ff4685dd…` (A).

## Result: the Section 5.1.2 client accepts genuine Evidence from the wrong machine

Acting as the client for each guest (recompute the binder from that guest's transcript and the
server key; verify the report's ECDSA-P384 signature with the VCEK; verify the VCEK chain to
AMD ARK-Milan fetched from the KDS), both are accepted:

| | binder matches | report signature | chain to ARK-Milan | `hwID == CHIP_ID` | **client accepts** | chip / place |
|---|---|---|---|---|---|---|
| honest, server S | yes | valid | valid | yes | **yes** | S, Iowa |
| attack, leaked key, A | yes | valid | valid | yes | **yes** | **A, Netherlands** |

The attacker's Evidence is not a replay and not a forgery: it is a fresh, genuine, KDS-verifiable
SEV-SNP report signed by the attacker's own chip in the Netherlands, bound to the attacker's own
live `ClientHello...ServerHello` with the client, under the leaked server key. The client's Section
5.1.2 check passes in full, yet the machine that signed is a different chip in a different country
from the server the client believes it reached. Files: `runs-early/server/20260911T220233Z`,
`runs-early/attacker/20260911T220142Z`; machine-checked in `runs.summary.json`.

## Why the transcript binding does not prevent this

Section 5.1.3 argues that binding to `Hash(ClientHello...ServerHello)` gives relay protection
because the two Hellos' randoms are fresh per connection. That defeats a **replay** of the server's
own report into another connection (we confirm this: presenting S's report on A's transcript fails
the binder, `poc_mock.py`). It does not defeat this attack, because the attacker does not replay:
the attacker is an **endpoint** of the connection with the client, so it chooses that transcript and
computes a fresh binder over it, then obtains a fresh report from a TEE it controls. The transcript
hash is public to the endpoints; only a value derived from the session's **shared secret** is not.

The draft states the intended defense in Section 5.1.3: an endorsed TEE "is required to verify the
binder against the TLS public key associated with the private key that it holds", so a compromised
host cannot use the TEE "as a signing oracle". On SEV-SNP there is no such check: the firmware signs
whatever `REPORT_DATA` the guest supplies and never inspects a TLS key. The check the draft relies
on is therefore an in-TEE application property, and Section 5.2 states its failure mode exactly:
if the TIK private key is generated outside the TEE (or, per *Intra-handshake.fail* 7.1.4, leaked,
provisioned at runtime, or extracted on another machine) "a relying party cannot detect this attack
unless additional safeguards are in place." This run is that failure, measured.

## Scope, stated honestly

- The attacker's report carries the attacker's **own** `CHIP_ID`, measurement, and (for a geographic
  Result) its own place: this attack lets the attacker pass off **its** machine as the peer, not put
  the server's identity or location into its own report. Its force is that the client cannot tell,
  from a 5.1.1-bound Evidence, that the signer is not its handshake peer.
- The fix is to bind Evidence to a value derived from the session's shared secret (the RFC 9266 TLS
  exporter), not to the public key. *Intra-handshake.fail* Section 7.2 shows that binding **both** the
  public key and the handshake-derived key holds as long as one of them is secret; binding the public
  key alone (Section 5.1.1, with or without a nonce: binder 4 and binder 6) does not.
- For draft-richardson-rats-geographic-results this is the "Relayed Results" consideration made
  concrete: a geographic Result must be bound to the session through the shared secret, or a relying
  party cannot be sure the Result describes the machine it is talking to.

## An incidental observation on 5.1.1

`c_attest_binder` and `s_attest_binder` use the same label `"attestation"` and differ only by which
public key is hashed; there is no client/server domain separation in the derivation. Two peers that
ever presented the same public key in the two roles would compute the same binder value.

## Reproduce

`binder.py` (the byte-exact 5.1.1 derivation, self-test in `__main__`), `handshake.py` /
`handshake_stdlib.py` (real TLS 1.3 transcript capture), `verify.py` + `poc_mock.py` (logic proof on
mock chips), `verify_run.py` (offline Section 5.1.2 verification of a two-guest run against the KDS).
The guest is `../gcp-cvm/probe-early-attest.sh`; launch two guests with one shared `tik-pem` in the
metadata and `role=server` / `role=attacker`.
