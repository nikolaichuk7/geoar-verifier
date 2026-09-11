#!/usr/bin/env python3
"""End-to-end logic proof on MOCK chips (no cloud), so the orchestration is verified before spend.

Two mock 'chips' S and A, each a P-384 key standing in for a VCEK, each with a distinct CHIP_ID.
A mock chip is a pure REPORT_DATA signing oracle: sign(report_data) -> a 1184-byte report with that
REPORT_DATA at 0x50, the chip's CHIP_ID at 0x1A0, signed over bytes[:0x2A0]. That is exactly what
SEV-SNP firmware does (it never inspects REPORT_DATA), so swapping a mock for a real guest is a
drop-in. Then:
  Honest:  server S computes s_attest_binder over the real handshake and asks its OWN chip to sign.
  Attack:  attacker A holds S's leaked TIK key, terminates the client, computes s_attest_binder over
           the attacker<->client transcript and S's public key, and asks ATTACKER's chip to sign.
The client runs Section 5.1.2 verification in both cases and we print what it accepts and from which
chip. Success of the attack = accept:true with chip_id == A, not S."""
import os, struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asn1
import binder as B
import verify as V

class MockChip:
    def __init__(self, name):
        self.name = name
        self.key = ec.generate_private_key(ec.SECP384R1())
        self.chip_id = os.urandom(64)  # distinct per chip, like a real CHIP_ID
    def cert_like(self):
        # a stand-in 'certificate': an object exposing public_key(), enough for verify.sig_ok
        pk = self.key.public_key()
        class C:
            def public_key(self_inner): return pk
        return C()
    def sign_report(self, report_data: bytes) -> bytes:
        assert len(report_data) == 64
        rep = bytearray(1184)
        rep[0x50:0x90] = report_data
        rep[0x1A0:0x1E0] = self.chip_id
        rep[0x140:0x160] = os.urandom(32)  # REPORT_ID
        der = self.key.sign(bytes(rep[:0x2A0]), ec.ECDSA(hashes.SHA384()))
        r, s = asn1.decode_dss_signature(der)
        rep[0x2A0:0x2A0+48] = r.to_bytes(48, "little")
        rep[0x2A0+72:0x2A0+120] = s.to_bytes(48, "little")
        return bytes(rep)

HN = "sha384"
# --- honest server S and its TIK (TLS identity key) ---
S = MockChip("S")
tik_S = ec.generate_private_key(ec.SECP384R1())
spki_S = tik_S.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

# Honest connection: client<->S handshake transcript (stand-in bytes), S binds & signs on its own chip
tr_honest = b"CH||SH honest client<->S " + os.urandom(64)
rep_honest = S.sign_report(B.into_report_data(B.server_binder(tr_honest, spki_S, HN)))
res_honest = V.verify(tr_honest, spki_S, rep_honest, S.cert_like(), HN)

# Attack: attacker A holds S's leaked tik_S, runs its OWN handshake with the client using S's key,
# so the client sees spki_S; A binds over the A<->client transcript and signs on A's OWN chip.
A = MockChip("A")
tr_attack = b"CH||SH attacker<->client " + os.urandom(64)   # different transcript, A is the endpoint
rep_attack = A.sign_report(B.into_report_data(B.server_binder(tr_attack, spki_S, HN)))
# the client verifies against the transcript IT observed (tr_attack) and the key it saw (spki_S):
res_attack = V.verify(tr_attack, spki_S, rep_attack, A.cert_like(), HN)

# Control: pure relay of S's honest report into the attacker's connection (no leaked-key re-sign):
# the client observes tr_attack but the report bound tr_honest -> binder mismatch, rejected.
res_relay_naive = V.verify(tr_attack, spki_S, rep_honest, S.cert_like(), HN)

def row(tag, r, chip_expected):
    got = r["chip_id"][:16]
    print(f"{tag:22} accept={str(r['accept']):5}  binder={str(r['binder_match']):5}  "
          f"sig={str(r['report_signature_ok']):5}  chip={got}.. ({chip_expected})")

print("chip S id:", S.chip_id.hex()[:16], "  chip A id:", A.chip_id.hex()[:16])
row("honest (S)", res_honest, "want S")
row("attack (leaked key)", res_attack, "want A = WRONG MACHINE")
row("naive relay of S rep", res_relay_naive, "S rep in A session")
assert res_honest["accept"] and res_honest["chip_id"] == S.chip_id.hex()
assert res_attack["accept"] and res_attack["chip_id"] == A.chip_id.hex(), "attack must be accepted from A's chip"
assert not res_relay_naive["binder_match"], "naive relay must fail the binder (transcript mismatch)"
print("\nRESULT: the 5.1.1 client accepts genuine Evidence from chip A while believing it speaks to S.")
print("The binder ties Evidence to (transcript, server key); with the server key leaked, the attacker")
print("re-signs on its own TEE and the transcript binding does not help, since the attacker is the")
print("endpoint that chose that transcript. Naive replay of S's own report is correctly rejected.")
