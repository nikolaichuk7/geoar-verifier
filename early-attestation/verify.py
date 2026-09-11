#!/usr/bin/env python3
"""Client-side verification for the Section 5.1.1 binder over a SEV-SNP report (Section 5.1.2).

Given the ClientHello...ServerHello transcript the client observed, the server SubjectPublicKeyInfo
it saw in the handshake, and the signed Evidence (a 1184-byte SEV-SNP attestation report plus the
certificate that signs it), the verifier:
  1. recomputes s_attest_binder (binder.server_binder) and checks REPORT_DATA == binder||0-pad;
  2. checks the report's ECDSA-P384 signature with the supplied chip certificate (a genuine report);
  3. returns the CHIP_ID the report actually came from.
Per Section 5.1.2 the client accepts iff (1) and (2) hold. It has no way, from the binder alone, to
require that CHIP_ID be any particular machine: that is the gap this PoC measures."""
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asn1
import binder as B

def parse_report(rep: bytes):
    return {
        "report_data": rep[0x50:0x90],
        "measurement": rep[0x90:0xC0].hex(),
        "chip_id": rep[0x1A0:0x1E0].hex(),
        "report_id": rep[0x140:0x160].hex(),
    }

def sig_ok(rep: bytes, cert) -> bool:
    r = int.from_bytes(rep[0x2A0:0x2A0+48], "little")
    s = int.from_bytes(rep[0x2A0+72:0x2A0+120], "little")
    try:
        cert.public_key().verify(asn1.encode_dss_signature(r, s), rep[:0x2A0], ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False

def verify(transcript: bytes, server_spki_der: bytes, report: bytes, chip_cert, hashname: str):
    want = B.into_report_data(B.server_binder(transcript, server_spki_der, hashname))
    f = parse_report(report)
    binder_ok = (f["report_data"] == want)
    signature_ok = sig_ok(report, chip_cert)
    return {
        "binder_match": binder_ok,           # Section 5.1.2 check
        "report_signature_ok": signature_ok, # genuine hardware Evidence
        "accept": binder_ok and signature_ok,# what the 5.1.2 client concludes
        "chip_id": f["chip_id"],             # which machine actually signed
        "report_id": f["report_id"],
    }
