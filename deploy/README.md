# PatchLock deployment

The hardened PatchLock contract is deployed on GenLayer Bradbury.

- Hardened canonical contract: `0xB448eE56C2E84b17c1643B07C462D9bFfB414f27`
- Deployment transaction: `0x234cc067d8f5d53a643d636658510f24b742a8e9e845639dd7e718c2ccbc50fe`
- Canonical hardened source commit: `72ecb3e757ab2ad21ddf675fc2f996aa88cd835e`
- Hardened deployed source was retrieved and verified.

**LEGACY / PRE-STEWARD-HARDENING.**

- Legacy contract: `0x92C621Ae9781c9b6695dfd5B6aeAe78b09cF7E71`
- Legacy deployment transaction: `0xb1d1883290f1e89bc31cd5f43df4861f0cbc12cabe3f23facfb75dedef3e0023`

The live hardened lifecycle is:

`REGISTER -> EDIT -> SEAL -> FULL-SOURCE REVIEW -> VERDICT -> can_release()`

Registration creates an unsealed release. The owner can edit policy and evidence sources until the irreversible seal. Sealing permanently locks both snapshots; it does not authorize release. Reviews are permissionless only after sealing and must use the complete frozen source set. Deployment authorization remains a read-only, contract-driven `can_release(release_id)` check.

## Live Bradbury evidence

- Release 1 registration succeeded.
- Release 1 seal succeeded.
- Two review attempts ended `LEADER_TIMEOUT` with no validator vote.
- Authoritative `review_count` was 0 after the first timeout and remained 0 after the later retry.
- The hardened deployment has not been live-proven to produce `CLEAR / BOUND` or `can_release = true`.
- Bradbury review smoke remains pending due network/consensus availability.
- Local regression coverage proves the positive authorization and sticky-block paths.
- No Review 1 is claimed for the hardened deployment because authoritative `get_review_count()` is 0.

Do not deploy again as part of routine validation. This directory is reserved for deployment configuration and scripts; it is not part of the release authorization path.

The prepared command is:

`/home/ini/.nvm/versions/node/v24.18.0/bin/genlayer deploy`
