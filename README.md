# geoar-verifier

**Where does a place enter an attestation artifact?** Measured on real hardware on 11 September 2026: AWS EC2 SEV-SNP (VLEK), Google Cloud SEV-SNP and Intel TDX, Azure SEV-SNP through the paravisor, plus the earlier AWS Nitro and Azure SGX corpus. Every signature verified against the vendor root with the independent code in this repository, every capture tied to a public nonce. The one-table view is **[ATLAS.md](ATLAS.md)**; the five verification protocols a Verifier can run today, each measured, are in **[PROTOCOLS.md](PROTOCOLS.md)**; the per-machine record built from every run (which chip signed, seen before or not) is **[LEDGER.md](LEDGER.md)**; the raw reports, certificates, chains, tokens and scripts are in `aws-vlek/`, `gcp-cvm/` and `azure-cvm/`.

A minimal Verifier chain for [draft-richardson-rats-geographic-results](https://datatracker.ietf.org/doc/draft-richardson-rats-geographic-results/)
with the `basis` and `claim-uuid` claims of PR #6 and the `basis-ref` / `observed-from` / `observed-until` proposal of PR #7.
Every vector is here as bytes and as CBOR diagnostic notation (`*.diag`), and every byte reproduces from fixed seeds.

    Attester (device)  -> 64 H3 res-10 cells, 15 min apart, each Ed25519-signed                        (Evidence)
    Verifier A         -> EAR, COSE_Sign1/EdDSA: jurisdiction-country, claim-uuid U1, basis = evidence  (R1, 25 bytes)
    Verifier B         -> EAR, COSE_Sign1/EdDSA: same country, claim-uuid U2, basis = attestation-result, basis-ref U1, observation window (R2, 57 bytes)
    Relying Party      -> verifies signatures against its trust anchors, walks basis-ref, applies an appraisal policy for results

## The evidence set

`vectors/trip_synthetic_example.ayerbe.json` was supplied verbatim by the author of draft-ayerbe-trip-protocol on 2026-09-10
(64 H3 resolution-10 cells across Utrecht, collection times 900 s apart, 15.75 h, labelled synthetic by its author). It carries no
signatures; `vectors/evidence-supplied-signed.json` is the same cells and times with each breadcrumb signed by the example's device
key, because a deployment signs each cell on the device. Verifier A: 64/64 signatures verified; 64/64 whole cells inside NL (Natural Earth 10m admin-0,
whole-cell containment). The claim-uuid is uuid5 of the SHA-256 of the signed set, so anyone holding the set can recompute it.

## Run

    pip install cbor2 cryptography h3 shapely pycose
    curl -LO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_0_countries.geojson
    python3 trip_chain.py ne_10m_admin_0_countries.geojson two-claims-check.cddl vectors/trip_synthetic_example.ayerbe.json
    python3 cbor_diag.py vectors/*.cbor vectors/*.cose        # diagnostic notation
    cddl two-claims-check.cddl validate vectors/r1-core.cbor  # gem install cddl

`two-claims-check.cddl` is the CDDL of PR #6 with the root rule first and the imported generics stubbed for the `cddl` gem;
`pr7-check.cddl` the same for PR #7; `ext-check.cddl` additionally admits label 15 (the provenance value of PR #4).

## Relying-party table (vectors/chain-report.json)

Policy "strict": trusted signer, EU country, basis evidence or endorsement; basis attestation-result only through a resolvable
basis-ref whose chain bottoms out in evidence or endorsement. Policy "lenient": trusted signer and EU country.

| case | strict | lenient |
|---|---|---|
| R1 EAR from A (evidence) | ACCEPT | ACCEPT |
| R2 EAR from B (attestation-result, basis-ref U1) | ACCEPT | ACCEPT |
| R2 without basis-ref | REJECT | ACCEPT |
| forged EAR, kid A, untrusted key | REJECT | REJECT |
| 26-run SEV-SNP NL (basis 2, no ref) | REJECT | ACCEPT |
| 26-run Azure NL (basis 1) | ACCEPT | ACCEPT |

Same four bytes `00 62 4e 4c` in every NL row; the only thing the strict policy reads differently is the basis.

The two NL results of the 26-artifact public-cloud run (Azure, basis endorsement; SEV-SNP, basis attestation-result) are in
`geoar-run-27-two-claims.json` as emitted; `vectors/ear-snp-nl.*` and `vectors/ear-azure-nl.*` are those payloads, bytes unchanged,
signed by Verifier A's key for the demo.

Apache-2.0. Serhii Nikolaichuk, Austin, Texas.
