# early-attestation: the draft-fossati-seat-early-attestation Section 5.1.1 binder on SEV-SNP

Measures the attestation binder of draft-fossati-seat-early-attestation-06 Section 5.1.1 on real
AMD SEV-SNP hardware and shows it does not tie Evidence to the endpoint once the server TLS
identity key is available to an attacker (leaked, provisioned at runtime, or extracted elsewhere).
See `RESULTS.md`. Reproduces on hardware the public-key-binder class of *Intra-handshake.fail*
(CVE-2026-33697, ESORICS 2026).

- `binder.py` — byte-exact Section 5.1.1 derivation (HKDF-Expand-Label per RFC 8446); `__main__` self-test.
- `handshake.py` / `handshake_stdlib.py` — real TLS 1.3 handshake (`ssl.MemoryBIO`), exact `ClientHello...ServerHello` capture, binder. The stdlib file has no third-party dependency and runs on the guest.
- `verify.py`, `poc_mock.py` — client verifier and an end-to-end logic proof on mock chips (no cloud).
- `verify_run.py` — offline Section 5.1.2 verification of a two-guest run: recompute the binder, verify the SEV-SNP signature and the VCEK chain to AMD ARK-Milan, print the decision table.
- `../gcp-cvm/probe-early-attest.sh` — the guest probe. Two guests are launched with the **same** `tik-pem` (the leaked key) and `role=server` / `role=attacker`.

No SSH, no inbound rule; the guest reports through the serial console. The injected TIK private key
is deleted on the guest before the archive is shipped and is never committed.
