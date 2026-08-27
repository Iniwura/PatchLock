# PatchLock

Intelligent software release quarantine and deployment authorization on GenLayer.

## Problem

PatchLock answers one narrow, security-sensitive question:

> Is this exact software release safe and compliant enough to ship under its release policy?

A project description, mutable policy, or unbound security filing is not enough. PatchLock binds every review to a concrete project/version/build identity, records who registered it, requires the owner to irreversibly seal the policy and complete evidence source set, and exposes a small authorization primitive for downstream release systems.

## Architecture

The contract at contracts/patchlock.py is the source of truth. It stores:

- exact release identity and the registering transaction sender;
- a policy snapshot and policy version;
- an evidence-source snapshot and source-set version;
- the latest strict verdict;
- a permanent blocked bit;
- append-only review history.

execution/patchlock_release_gate.py is the repository-level reference consumer. It rereads can_release(release_id) for every deployment attempt and calls the downstream target only after authorization succeeds.

The deploy/ directory contains the Bradbury deployment note and a non-executed deployment helper. The currently deployed address is a legacy pre-steward-hardening contract; the hardened contract in this branch has not been deployed.

## Release identity

register_release requires non-empty:

- project_name;
- semantic/version string;
- commit_hash;
- artifact_hash;
- manifest_hash;
- sbom_hash;
- release policy;

policy_version and source_set_version are system-controlled counters. Registration starts both at 1; successful pre-seal updates increment the relevant counter.

The transaction sender becomes release_signer. This proves that the GenLayer transaction signer registered these exact identifiers onchain. PatchLock does not claim to cryptographically verify an arbitrary external CI signature; no external signature verification is implemented here.

There is no write method that changes any identity field. A fixed artifact must be represented by a new release record with a new build identity.

## Policy locking

A registered release starts editable. The owner may update the policy and its system-controlled policy_version before sealing.

seal_release is owner-only and irreversible. It freezes release_policy, policy_version, evidence_sources, and source_set_version without authorizing release or creating a Review.

review_release is permissionless but requires sealed == True. It copies the identity, policy, versions, and complete frozen source set into plain memory before nondeterministic evaluation. review_started means that at least one Review was successfully persisted; it is not the locking primitive.

GenLayer executes each transaction to completion without another write interleaving. A failed sealed review therefore creates no Review and leaves the already-sealed snapshot unchanged.

## Evidence source versioning

Registration snapshots evidence_sources and source_set_version. The configured source set contains 1 to 4 unique exact HTTP(S) strings. The owner may update it before sealing; each successful update increments source_set_version by one. seal_release freezes the complete set. Every review must submit the entire frozen set: no subset, superset, duplicate, unregistered URL, normalization, domain matching, or alternate spelling is accepted.

Review evidence is recorded per review. Because every review evaluates the complete frozen source set, every configured source is fetched. A real HTTP response, including 4xx/5xx and an empty body, is usable evidence; transport failures are recorded as unavailable; HTTP status alone never implies vulnerability or safety; bodies are bounded before evaluation. If any frozen source is unavailable, a proposed CLEAR is deterministically normalized to UNDETERMINED.

Each Review snapshots policy_version and source_set_version. Historical source observations therefore remain tied to the exact policy/source configuration used for that review.

## Evidence replay and grinding protection

For every adjudication, PatchLock computes a deterministic SHA-256 commitment over release_id, every immutable identity field, policy_version, source_set_version, the complete frozen source URL set, every fetched HTTP status, every bounded usable body, and an unavailable marker plus error type for transport failures. URL ordering, review title, and claimed risk do not alter the commitment. The commitment is itself consensus-critical: validators must independently agree on it before the review can be accepted, and a release cannot accept the same commitment twice. SHA-256 is a deterministic packet fingerprint, not an external signature or proof that the remote source is honest. Stable, immutable, or content-addressed evidence is preferred for high-assurance integrations; mutable endpoints can cause validator disagreement and unresolved transactions, and PatchLock fails closed for safety.


## Evidence binding

The evaluator receives the exact project, version, commit, artifact, manifest, and SBOM identifiers, the sealed policy/version, the complete frozen source set/version, the review claim, and every fetched evidence item. It is explicitly instructed not to treat generic project evidence or an unrelated version as release-specific. Blocking evidence from any sufficiently bound source must be considered; a favorable source must not erase conflicting blocking evidence. CLEAR requires the complete packet to support shipment.

The contract independently enforces the key consequence: can_release requires both a CLEAR verdict and BOUND release binding. PARTIAL and UNBOUND evidence can be retained in review history but never authorize shipment. A BLOCKED result is only sticky when its binding is BOUND; a weakly bound blocking claim is conservatively downgraded to UNDETERMINED.

HTTP status alone never implies vulnerability or safety.

## Verdicts

Every successful evaluator result must be strict JSON with exactly these string keys:

~~~json
{
  "verdict": "CLEAR | CAUTION | BLOCKED | UNDETERMINED",
  "release_binding": "BOUND | PARTIAL | UNBOUND",
  "reasoning": "string",
  "evidence_summary": "string"
}
~~~

Malformed JSON, non-object values, missing keys, extra keys, wrong types, invalid enum values, and malformed evidence commitments are rejected. The evaluator response remains exactly the four JSON keys shown above; PatchLock adds the deterministic evidence_commitment after validation. Validators compare verdict, release_binding, and the 64-hex commitment; long free-form fields are retained but are not consensus comparison fields.

- CLEAR requires sufficient evidence under the policy and must be BOUND to authorize.
- CAUTION records a meaningful concern without an established block.
- BLOCKED requires a policy-supported blocking condition tied to the exact release.
- UNDETERMINED covers unavailable, conflicting, insufficient, or unbound evidence.

## Sticky blocking

Once a sufficiently bound BLOCKED review is accepted, release.blocked becomes True permanently. Later CLEAR, CAUTION, or UNDETERMINED reviews update the latest-review fields but never reset the bit. There is no unblock, reset, pardon, or identity mutation method.

Deactivation is independent from blocking. A release may be reactivated before or after blocking, but can_release still returns False for a blocked release. The only path for a fixed artifact is a new release registration with a new artifact/build identity.


## Public API

The final public surface is exactly 11 methods:

- Views: get_release_count(), get_review_count(), get_release(release_id), get_review(review_id), can_release(release_id).
- Writes: register_release(...), seal_release(release_id), review_release(...), update_release_policy(release_id, release_policy), update_evidence_sources(release_id, evidence_sources), set_release_active(release_id, active).

There is no unblock, reset, pardon, identity mutation, or convenience method that bypasses authorization.

## can_release()

can_release(release_id) returns True only when:

1. the release exists;
2. it is active;
3. it is not permanently blocked;
4. its latest verdict is CLEAR;
5. its latest release binding is BOUND.

Fresh, CAUTION, UNDETERMINED, BLOCKED, weakly bound CLEAR, and inactive releases all return False.

## PatchLockReleaseGate

The reference adapter has two distinct failure classes:

- ReleaseBlocked: authorization was false or the authorization read failed; execution fails closed and the target is not called.
- ReleaseExecutionFailed: authorization succeeded but deployment_target.deploy(payload) failed.

The gate performs no authorization caching. CI/CD, deployment services, and other protected execution paths should use this boundary or an equivalent fresh can_release read. A frontend display is not a security boundary.

## Threat model

PatchLock is designed against:

- vague descriptions that do not identify a build;
- evidence whose provenance is weak or about another release;
- changing the release rule after seeing evidence;
- changing monitored sources after owner seal;
- strategically filing favorable reviews after a block;
- overwriting review history;
- treating caution or missing evidence as authorization;
- stale authorization cached by a downstream consumer;
- deactivation/reactivation being used to erase a block.

Reviews are permissionless by design. A stranger can submit a review claim, but cannot inject an unregistered URL, alter the frozen policy/source set, or directly write a verdict. A fabricated claim alone is not authorization: only a consensus-accepted CLEAR with BOUND release_binding can make can_release true. Generic or unrelated evidence should be judged PARTIAL/UNBOUND and is conservatively non-authorizing; validator/LLM mistakes remain an inherent limitation.

PatchLock does not verify arbitrary external CI signatures, prove that an external repository is honest, or make an unimplemented claim about the contents of an artifact. It records the exact release identifiers signed by the GenLayer transaction sender and asks GenLayer validators to judge fetched evidence against the frozen review context.


## 400-point adversarial guarantees

**A. Can evidence be about a different release?**
An arbitrary source URL cannot be submitted: exact membership in the frozen registered source set is enforced. The content at an allowed source can still discuss another release; the evaluator must mark weak binding as PARTIAL or UNBOUND, neither of which authorizes. Generic-project or unrelated-version evidence cannot produce authorized CLEAR.

**B. Can the owner change policy after seeing an unfavorable review?**
No. The owner may change policy before seal_release. Once sealed, release_policy and policy_version are immutable. A failed sealed review creates no history but cannot reopen or alter that frozen context.

**C. Can the owner change evidence sources after review begins?**
No. The owner may change evidence_sources before seal_release. Once sealed, the complete source set and source_set_version are immutable, and every review must evaluate every frozen source.

**D. Can a favorable filing erase BLOCKED?**
No. blocked is permanent and no write method clears it.

**E. Can a blocked artifact be fixed in-place?**
No. A new artifact/build identity requires a new release registration.

**F. Can a frontend bypass PatchLock?**
Only an unprotected external integration could do so. Protected execution must call can_release through PatchLockReleaseGate or an equivalent enforcement boundary; UI state is not authorization.

**G. Can stale cached authorization allow deployment?**
The reference gate does not cache. It rereads authorization on every execute call and fails closed on read errors.

## Testing

The suite uses the installed Direct Mode environment and has separate contract and execution-gate coverage. It includes registration validation, identity immutability, policy/source locking, provenance and URL behavior, strict schema checks, all verdicts, authorization, sticky blocking, ownership, history, and fail-closed execution.

From this project, with the compatible WSL environment:

~~~text
gltest -q
python -m pytest -q
genvm-lint lint contracts/patchlock.py
genvm-lint validate contracts/patchlock.py
genvm-lint schema contracts/patchlock.py
genvm-lint typecheck contracts/patchlock.py
~~~

## Frontend

The local React/Vite frontend lives in app/. It is an operational read surface for the pre-hardening ten-method ABI and is intentionally unchanged in this branch:

- public release and review reads continue without a wallet;
- registration and review forms use the exact contract argument order;
- review evidence is selected only from the release's frozen, exact source strings;
- registration and review writes resolve their record IDs from authoritative post-write reads;
- policy, source-set, active-state, and review writes require readable state confirmation before completion;
- the deployment page reads can_release() only and never pretends to deploy;
- external protected execution must use PatchLockReleaseGate or an equivalent fresh authorization boundary.

The wallet integration uses the installed genlayer-js 1.2.0 Bradbury definition and an injected EIP-1193 provider. It does not use MetaMask Snaps or client.connect(). The unchanged frontend still targets the legacy ABI/address until a hardened contract is deployed; it contains no fabricated release data. A later frontend pass must add seal_release/sealed lifecycle handling, require the complete frozen source set for reviews, and rewire the address and ABI to the hardened deployment.

The UI preserves the contract's security model: exact release identity is readable, policy and source versions are visible per review, non-BOUND CLEAR results are shown as non-authorizing, sticky BLOCKED records receive a permanent quarantine seal, and a corrected artifact is presented as a new release rather than an in-place rehabilitation.

## Deployment

**BRADBURY / LEGACY / PRE-STEWARD-HARDENING.**

- Network: Bradbury
- Legacy contract: `0x92C621Ae9781c9b6695dfd5B6aeAe78b09cF7E71`
- Legacy deployment transaction: `0xb1d1883290f1e89bc31cd5f43df4861f0cbc12cabe3f23facfb75dedef3e0023`


The legacy address and transaction above are retained only as historical live proof. The steward-hardened contract in this branch is NOT DEPLOYED and has no canonical address or transaction hash yet. No deployment is performed by this repository. The prepared helper remains at `deploy/deployScript.ts`; it reads the contract, submits `args: []`, waits for ACCEPTED, requires AGREE and a valid address, and prints the transaction hash and address.

## LIVE BRADBURY PROOF

The following observations are historical live proof for the legacy pre-steward-hardening Bradbury deployment only; they do not prove the hardened contract is deployed.

### CLEAR path

`REGISTERED -> CLEAR + BOUND -> can_release(1) = true`

- Release 1 registration transaction: `0x4bee5a93cb8f16b0c8006c5c48401a873144a6916dc3bb27dfcef1c5297a4d7a`.
- Accepted review transaction: `0xa5ea8543301eb21ae4c2ba941f687637aa681f05d8aa6a51f68b277e84e615de`.
- Final observed state: release 1, CLEAR, BOUND, blocked false, `can_release(1) = true`.

### Permanent quarantine path

`REGISTERED -> BLOCKED + BOUND -> blocked = true -> can_release(2) = false`

- Accepted blocking review transactions: `0xb3191a09f7dec153e646afc22991ff4fa20a4641165594ec2e16f6c12e75b71e` and `0xedd3d08cb679266b18709edd4f94b802ded62fa0bd121afef36eb32584ff764d`.
- Final observed state: release 2, BLOCKED, BOUND, blocked true, `can_release(2) = false`.
- Global accepted review count after this proof: 3.

### Later favorable filing

The later favorable filing transaction was `0x8d64ddb4a0179a941ce38c0bf7aeadb4801d803124fc8f872eef923ab2d4f56f`. Its final observed status was **Undetermined** with `statusCode: 6`. It was not accepted, did not produce CLEAR, and did not mutate authoritative accepted state. Release 2 remained BLOCKED/BOUND with blocked true and `can_release(2) = false`.

This live observation does not claim that the network accepted a favorable review after a block, and it does not claim that live Bradbury proved CLEAR-after-BLOCKED persistence. The local contract regression suite separately proves that later accepted favorable verdicts cannot clear the sticky blocked flag.

### Limitations

- PatchLock does not independently verify external CI signatures.
- Remote evidence-source authenticity is not independently proven.
- Exact packet replay protection does not prevent semantically near-duplicate evidence.
- Nondeterministic GenLayer judgment remains part of review.
- Downstream systems must consume `can_release()` through a real fail-closed gate such as `PatchLockReleaseGate`; frontend display is not authorization.

## Repository layout

~~~text
contracts/patchlock.py              PatchLock Intelligent Contract
test/test_patchlock.py              Direct Mode adversarial contract suite
test/test_execution_gate.py         Repository-level gate tests
execution/patchlock_release_gate.py Reference fail-closed consumer
deploy/deployScript.ts              Non-executed Bradbury deployment helper
pytest.ini                          Direct Mode test path configuration
~~~
