# Ledger: the per-machine record a verifier keeps (protocol 1)

One row per run that produced SEV-SNP reports. `key` is the SPKI SHA-256 of the certificate that verifies every report of the run: the VCEK that AMD KDS issues for the run's CHIP_ID and TCB (fetched when this table was built), or the VLEK the hypervisor supplied. Full values are in `ledger.json`; the reports themselves are in the run directories.

| cloud | run | captured (UTC) | key | CHIP_ID | key SPKI SHA-256 | TCB bl.tee.snp.ucode | REPORT_ID | reports | signatures |
|---|---|---|---|---|---|---|---|---|---|
| gcp | rats-snp-europe-west4-a | 2026-09-11 00:50Z | VCEK | 15f90cb088627a60… | 0387a84e406b3f45… | 4.0.29.222 | 59d1b08b38ac29c7… | 2 | OK |
| gcp | rats-snp-europe-west4-b | 2026-09-11 00:55Z | VCEK | 99e6176ce83fda32… | 52ecebef81704067… | 4.0.29.222 | 70b94574218dee23… | 2 | OK |
| gcp | rats-snp-us-central1-b-bind | 2026-09-11 13:42Z | VCEK | a2b2580a8a9e3064… | dc99adcea377f109… | 4.0.29.222 | 979a12c6a81c912c… | 3 | OK |
| gcp | rats-snp-us-central1-b-cos | 2026-09-11 00:59Z | VCEK | f1cf2d6fac9e8040… | 25d50d5c674d76b6… | 4.0.29.222 | af56a783aa61aaac… | 1 | OK |
| gcp | rats-snp-us-central1-b-cos2 | 2026-09-11 01:05Z | VCEK | da7f959f9936e0f8… | c9866e15cc7c510d… | 4.0.29.222 | 3d273dbd93dd1b69… | 1 | OK |
| gcp | rats-snp-us-central1-b-cos3 | 2026-09-11 01:16Z | VCEK | 28e9aeb5bfc75726… | 2683ec360e039272… | 4.0.29.222 | 9ec3704fa374de47… | 1 | OK |
| gcp | rats-snp-us-central1-b-dual4 | 2026-09-11 13:17Z | VCEK | 24d9104938ca35bd… | 95a1042bdd3272b0… | 4.0.29.222 | bff9a1a26449db29… | 5 | OK |
| gcp | rats-snp-us-central1-b-dual5 | 2026-09-11 13:17Z | VCEK | da7f959f9936e0f8… | c9866e15cc7c510d… | 4.0.29.222 | a221276c5cc95436… | 5 | OK |
| gcp | rats-snp-us-central1-b-dual6 | 2026-09-11 13:17Z | VCEK | 28e9aeb5bfc75726… | 2683ec360e039272… | 4.0.29.222 | 3c71d10d87f6ebeb… | 5 | OK |
| gcp | rats-snp-us-central1-b-reattest | 2026-09-11 13:41Z | VCEK | f1cf2d6fac9e8040… | 25d50d5c674d76b6… | 4.0.29.222 | 08c80326bc518644… | 10 | OK |
| gcp | rats-snp-us-central1-b-reattest | 2026-09-11 13:46Z | VCEK | f1cf2d6fac9e8040… | 25d50d5c674d76b6… | 4.0.29.222 | aa4ef53dd9d4e1b8… | 10 | OK |
| gcp | rats-snp-us-central1-b | 2026-09-11 00:51Z | VCEK | f1cf2d6fac9e8040… | 25d50d5c674d76b6… | 4.0.29.222 | a31ca1be5adb1a60… | 2 | OK |
| azure | rats-snp-eastus-3 | 2026-09-11 01:38Z | VCEK | 294602de49aec498… | bac46511deb2fcc3… | 4.0.24.219 | f1309e1a9ee753fe… | 1 | OK |
| azure | rats-snp-eastus | 2026-09-11 01:07Z | VCEK | 24f37eaafea80dae… | 73cfade7fbd65889… | 4.0.24.219 | c793eb773d4ba01f… | 1 | OK |
| azure | rats-snp-westeurope-2 | 2026-09-11 01:21Z | VCEK | 4f939e7a6b883deb… | 2dba7acbad0cb5e8… | 4.0.24.219 | 33a6eb6379a4fb89… | 1 | OK |
| azure | rats-snp-westeurope | 2026-09-11 01:09Z | VCEK | 92a89c018c917616… | b8448bff589cc4b9… | 4.0.24.219 | ba72972c081e1be7… | 1 | OK |
| aws | i-02587934b18bc3016 | 2026-09-11 13:16Z | VLEK (CN=cc-us-east-2.amazonaws.com) | all zeros | 5330c95b9cd4976c… | 4.0.29.222 | ae4b8b1bba9b861b… | 4 | OK |
| aws | i-036d8dbd13f29cba2 | 2026-09-11 12:57Z | VLEK (CN=cc-us-east-2.amazonaws.com) | all zeros | 5330c95b9cd4976c… | 4.0.29.222 | 21d6df81cec11674… | 2 | OK |
| aws | i-03dcf507880e1961e | 2026-09-11 13:16Z | VLEK (CN=cc-eu-west-1.amazonaws.com) | all zeros | 6f718ce827693226… | 4.0.29.222 | 121a50ef8935d165… | 4 | OK |
| aws | i-0603037ab5b36aada | 2026-09-11 13:24Z | VLEK (CN=cc-us-east-2.amazonaws.com) | all zeros | 5330c95b9cd4976c… | 4.0.29.222 | 43db6c125e3450f0… | 1 | OK |
| aws | i-0bf334666a8c4868c | 2026-09-11 00:12Z | VLEK (CN=cc-eu-west-1.amazonaws.com) | all zeros | 6f718ce827693226… | 4.0.29.222 | d0965113a4188af5… | 2 | OK |
| aws | i-0d7bec270b4f73618 | 2026-09-11 00:12Z | VLEK (CN=cc-us-east-2.amazonaws.com) | all zeros | 5330c95b9cd4976c… | 4.0.29.222 | cb5df5e1bedd2315… | 2 | OK |

## Machines seen more than once (11 distinct CHIP_ID values across 16 VCEK-signed runs)

| CHIP_ID | runs (captured) |
|---|---|
| 15f90cb088627a60… | rats-snp-europe-west4-a (2026-09-11 00:50Z) |
| 99e6176ce83fda32… | rats-snp-europe-west4-b (2026-09-11 00:55Z) |
| a2b2580a8a9e3064… | rats-snp-us-central1-b-bind (2026-09-11 13:42Z) |
| f1cf2d6fac9e8040… | rats-snp-us-central1-b-cos (2026-09-11 00:59Z); rats-snp-us-central1-b-reattest (2026-09-11 13:41Z); rats-snp-us-central1-b-reattest (2026-09-11 13:46Z); rats-snp-us-central1-b (2026-09-11 00:51Z) |
| da7f959f9936e0f8… | rats-snp-us-central1-b-cos2 (2026-09-11 01:05Z); rats-snp-us-central1-b-dual5 (2026-09-11 13:17Z) |
| 28e9aeb5bfc75726… | rats-snp-us-central1-b-cos3 (2026-09-11 01:16Z); rats-snp-us-central1-b-dual6 (2026-09-11 13:17Z) |
| 24d9104938ca35bd… | rats-snp-us-central1-b-dual4 (2026-09-11 13:17Z) |
| 294602de49aec498… | rats-snp-eastus-3 (2026-09-11 01:38Z) |
| 24f37eaafea80dae… | rats-snp-eastus (2026-09-11 01:07Z) |
| 4f939e7a6b883deb… | rats-snp-westeurope-2 (2026-09-11 01:21Z) |
| 92a89c018c917616… | rats-snp-westeurope (2026-09-11 01:09Z) |

Reading: a CHIP_ID that comes back in a later run is the same machine seen again (the KDS certificate for it verifies both runs' reports); a run whose reports show two CHIP_ID values would be a VM that moved between reports (none so far). REPORT_ID is per guest and changes at every launch, CHIP_ID does not.
