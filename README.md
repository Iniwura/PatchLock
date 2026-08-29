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

The deploy/ directory contains the Bradbury deployment note and a non-executed deployment helper. The hardened contract is deployed at the canonical address recorded below; the legacy address remains documented only as LEGACY / PRE-STEWARD-HARDENING.

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

For every adjudication, PatchLock computes a deterministic SHA-256 commitment over release_id, every immutable identity field, policy_version, source_set_version, the complete frozen source URL set, every fetched HTTP status, every bounded usable body, and an unavailable marker plus error type for transport failures. The frozen source URLs are sorted before fetching, evaluation, prompt construction, commitment, and Review storage, so reviewer ordering cannot alter adjudication. Review title and claimed risk are metadata only and do not enter the prompt or commitment. The commitment is itself consensus-critical: validators must independently agree on it before the review can be accepted, and a release cannot accept the same commitment twice. SHA-256 is a deterministic packet fingerprint, not an external signature or proof that the remote source is honest. Stable, immutable, or content-addressed evidence is preferred for high-assurance integrations; mutable endpoints can cause validator disagreement and unresolved transactions, and PatchLock fails closed for safety.


## Evidence binding

The evaluator receives only the exact project, version, commit, artifact, manifest, and SBOM identifiers, the sealed policy/version, the complete frozen source set/version, and every fetched evidence item in canonical URL order. Title and claimed_risk remain in Review history but are metadata only and never enter adjudication. Evidence, URLs, metadata, response bodies, and embedded text are explicitly delimited as untrusted data; commands or attempts to override verdict rules, schema, policy, identity, or validator instructions are ignored. The evaluator must not treat generic project evidence or an unrelated version as release-specific. Blocking evidence from any sufficiently bound source must be considered; a favorable source must not erase conflicting blocking evidence. CLEAR requires the complete packet to support shipment.

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

Reviews are permissionless by design. A stranger can submit metadata and a review over the complete frozen source set, but cannot inject an unregistered URL, alter the frozen policy/source set, or directly write a verdict. Title and claimed_risk are stored for history but are not adjudication inputs. A fabricated claim alone is not authorization: only a consensus-accepted CLEAR with BOUND release_binding can make can_release true. Generic or unrelated evidence should be judged PARTIAL/UNBOUND and is conservatively non-authorizing; validator/LLM mistakes remain an inherent limitation.

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

The local React/Vite frontend lives in app/ and targets the hardened 11-method Bradbury API at the canonical deployment address:

- public release, review, and authorization reads continue without a wallet;
- registration creates an unsealed release; the owner can edit policy and sources, then irreversibly seal the release;
- sealed releases show POLICY + SOURCES LOCKED and expose permissionless full-source review;
- review forms display every frozen source read-only and submit the complete release.evidence_sources set automatically;
- review title and claimed risk are reviewer metadata; adjudication authority remains the sealed release context plus fetched evidence;
- registration, seal, review, policy, source-set, and active-state writes require authoritative post-write confirmation;
- the deployment page calls can_release() read-only, distinguishes confirmed FALSE from READ FAILED / AUTHORIZATION UNKNOWN, and never pretends to deploy;
- external protected execution must use PatchLockReleaseGate or an equivalent fresh authorization boundary.

The wallet integration uses the installed genlayer-js 1.2.0 Bradbury definition and an injected EIP-1193 provider. It preserves direct eth_requestAccounts, eth_chainId, and wallet_switchEthereumChain handling, does not use MetaMask Snaps or client.connect(), and retains the walletless read path. No release or review data is fabricated when RPC state cannot be read.

The UI preserves the contract's security model: exact release identity is readable, sealed/policy/source versions and review_count remain visible, non-BOUND CLEAR results are shown as non-authorizing, sticky BLOCKED records receive a permanent quarantine seal, and a corrected artifact is presented as a new release rather than an in-place rehabilitation.

## Deployment

**BRADBURY / HARDENED / CANONICAL.**

- Network: Bradbury
- Hardened canonical contract: `0xB448eE56C2E84b17c1643B07C462D9bFfB414f27`
- Deployment transaction: `0x234cc067d8f5d53a643d636658510f24b742a8e9e845639dd7e718c2ccbc50fe`
- Source commit: `72ecb3e757ab2ad21ddf675fc2f996aa88cd835e`
- Hardened deployed source was retrieved and verified.
- No deployment is performed by this repository during validation. The prepared helper remains at `deploy/deployScript.ts`.

**LEGACY / PRE-STEWARD-HARDENING.**

- Legacy contract: `0x92C621Ae9781c9b6695dfd5B6aeAe78b09cF7E71`
- Legacy deployment transaction: `0xb1d1883290f1e89bc31cd5f43df4861f0cbc12cabe3f23facfb75dedef3e0023`

The legacy address, transaction, and historical Releases 1/2/3 are not records from the hardened deployment.

## LIVE BRADBURY EVIDENCE

The hardened Bradbury smoke evidence is intentionally limited:

- Release 1 registration succeeded on the hardened contract.
- Release 1 seal succeeded on the hardened contract.
- Two review attempts ended `LEADER_TIMEOUT` with no validator vote.
- Authoritative state showed `review_count = 0` after the first timeout and remained `review_count = 0` after the later retry.
- The hardened deployment has not been live-proven to produce `CLEAR / BOUND` or `can_release = true`.
- The Bradbury review smoke remains pending because network/consensus availability did not provide an accepted review.
- The local regression suite proves the positive authorization path and the sticky-block path.

The live lifecycle is:

`REGISTER -> EDIT -> SEAL -> FULL-SOURCE REVIEW -> VERDICT -> can_release()`

No Review 1 is fabricated for the hardened deployment because authoritative `get_review_count()` is 0.

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
