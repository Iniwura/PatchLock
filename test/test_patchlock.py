import sys

import pytest


REVIEW_URLS = [
    "https://evidence.example/advisory",
    "https://evidence.example/scan",
    "https://evidence.example/attestation",
    "https://evidence.example/incident",
]
SOURCE_URLS = REVIEW_URLS[:]
TOO_MANY_SOURCES = ["https://security.example/source-" + str(i) for i in range(15)]
PROMPT_MARKER = (
    "Evaluate whether the exact registered software release is safe and compliant "
    "under its release policy."
)
PROJECT = "PatchLock Demo"
VERSION = "1.2.3"
COMMIT = "commit-" + "a" * 40
ARTIFACT = "sha256:" + "b" * 64
MANIFEST = "sha256:" + "c" * 64
SBOM = "sha256:" + "d" * 64
POLICY = (
    "Block if evidence establishes a critical vulnerability exploitable in the "
    "shipped artifact, a compromised dependency, a failed mandatory security "
    "control, or a materially false release attestation."
)


def deploy(direct_vm, direct_deploy):
    direct_vm.check_pickling = True
    return direct_deploy("patchlock.py")


def register(
    contract,
    project_name=PROJECT,
    version=VERSION,
    commit_hash=COMMIT,
    artifact_hash=ARTIFACT,
    manifest_hash=MANIFEST,
    sbom_hash=SBOM,
    release_policy=POLICY,
    evidence_sources=None,
):
    return contract.register_release(
        project_name,
        version,
        commit_hash,
        artifact_hash,
        manifest_hash,
        sbom_hash,
        release_policy,
        SOURCE_URLS[:] if evidence_sources is None else evidence_sources,
    )


def get_release(contract, release_id=1):
    return contract.get_release(release_id)


def get_review(contract, review_id):
    return contract.get_review(review_id)


def owner_hex(contract, address):
    module = sys.modules[type(contract).__module__]
    return module.Address(address).as_hex.lower()


def setup(
    direct_vm,
    verdict="CLEAR",
    release_binding="BOUND",
    reasoning="Evidence supports the exact release under the frozen policy.",
    summary="Exact-release evidence reviewed.",
    urls=None,
    status=200,
    body="Evidence names PatchLock Demo 1.2.3 and the registered commit.",
):
    actual_urls = REVIEW_URLS[:1] if urls is None else urls
    direct_vm.clear_mocks()
    for url in actual_urls:
        direct_vm.mock_web(url, {"method": "GET", "status": status, "body": body})
    direct_vm.mock_llm(
        PROMPT_MARKER,
        {
            "verdict": verdict,
            "release_binding": release_binding,
            "reasoning": reasoning,
            "evidence_summary": summary,
        },
    )


def setup_raw_llm(direct_vm, response, urls=None):
    actual_urls = REVIEW_URLS[:1] if urls is None else urls
    direct_vm.clear_mocks()
    for url in actual_urls:
        direct_vm.mock_web(url, {"method": "GET", "status": 200, "body": "release evidence"})
    direct_vm.mock_llm(PROMPT_MARKER, response)


def review(
    contract,
    release_id=1,
    title="Security review",
    claimed_risk="No known material risk",
    urls=None,
):
    actual_urls = REVIEW_URLS[:1] if urls is None else urls
    return contract.review_release(release_id, title, claimed_risk, actual_urls)


def test_initial_counts_are_zero(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    assert int(contract.get_release_count()) == 0
    assert int(contract.get_review_count()) == 0


def test_valid_release_persists_exact_identity_policy_and_sources(
    direct_vm, direct_deploy, direct_alice
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    release_id = register(contract)
    stored = get_release(contract, release_id)
    assert int(release_id) == 1
    assert stored.project_name == PROJECT
    assert stored.version == VERSION
    assert stored.commit_hash == COMMIT
    assert stored.artifact_hash == ARTIFACT
    assert stored.manifest_hash == MANIFEST
    assert stored.sbom_hash == SBOM
    assert stored.release_policy == POLICY
    assert stored.policy_version == 1
    assert list(stored.evidence_sources) == SOURCE_URLS
    assert stored.source_set_version == 1
    assert str(stored.release_signer).lower() == owner_hex(contract, direct_alice)
    assert stored.review_started is False
    assert int(stored.review_count) == 0
    assert stored.latest_verdict == "UNDETERMINED"
    assert stored.latest_release_binding == "UNBOUND"
    assert stored.blocked is False
    assert stored.active is True


def test_release_ids_increment_and_owner_is_sender(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    first = register(contract, project_name="First")
    direct_vm.sender = direct_bob
    second = register(contract, project_name="Second", artifact_hash="sha256:" + "e" * 64)
    assert [int(first), int(second)] == [1, 2]
    assert int(contract.get_release_count()) == 2
    assert str(get_release(contract, second).release_signer).lower() == owner_hex(
        contract, direct_bob
    )


@pytest.mark.parametrize(
    "field",
    ["project_name", "version", "commit_hash", "artifact_hash", "manifest_hash", "sbom_hash"],
)
@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_registration_rejects_empty_identity_fields(
    direct_vm, direct_deploy, field, value
):
    contract = deploy(direct_vm, direct_deploy)
    with direct_vm.expect_revert():
        register(contract, **{field: value})


@pytest.mark.parametrize("field", ["release_policy"])
def test_registration_rejects_empty_control_fields(direct_vm, direct_deploy, field):
    contract = deploy(direct_vm, direct_deploy)
    with direct_vm.expect_revert():
        register(contract, **{field: " "})


@pytest.mark.parametrize(
    "bad_sources",
    [
        TOO_MANY_SOURCES,
        ["ftp://bad"],
        ["not-a-url"],
    ],
)
def test_registration_rejects_invalid_source_sets(direct_vm, direct_deploy, bad_sources):
    contract = deploy(direct_vm, direct_deploy)
    with direct_vm.expect_revert():
        register(contract, evidence_sources=bad_sources)


def test_fresh_release_is_not_authorized(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    assert contract.can_release(1) is False


def test_no_identity_mutation_methods_exist(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    forbidden = [
        "update_release_identity",
        "update_commit_hash",
        "update_artifact_hash",
        "update_manifest_hash",
        "update_sbom_hash",
    ]
    assert all(not hasattr(contract, name) for name in forbidden)


def test_owner_can_update_policy_before_first_review(
    direct_vm, direct_deploy, direct_alice
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    contract.update_release_policy(1, "Stricter policy")
    stored = get_release(contract)
    assert stored.release_policy == "Stricter policy"
    assert stored.policy_version == 2
    assert stored.review_started is False


def test_non_owner_cannot_update_policy(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only release owner"):
        contract.update_release_policy(1, "Unauthorized")


@pytest.mark.parametrize(
    "policy", ["", " "]
)
def test_policy_update_rejects_empty_values(direct_vm, direct_deploy, policy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert():
        contract.update_release_policy(1, policy)
    stored = get_release(contract)
    assert stored.release_policy == POLICY
    assert stored.policy_version == 1


def test_policy_update_is_rejected_after_first_review(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm)
    review(contract)
    with direct_vm.expect_revert("policy is locked"):
        contract.update_release_policy(1, "Favorable policy")


def test_failed_post_review_policy_mutation_leaves_version_unchanged(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm)
    review(contract)
    before = get_release(contract)
    with direct_vm.expect_revert():
        contract.update_release_policy(1, "Changed after review")
    after = get_release(contract)
    assert after.release_policy == before.release_policy
    assert after.policy_version == before.policy_version


def test_owner_can_update_sources_before_first_review(
    direct_vm, direct_deploy, direct_alice
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    replacement = ["https://security.example/new-feed"]
    contract.update_evidence_sources(1, replacement)
    stored = get_release(contract)
    assert list(stored.evidence_sources) == replacement
    assert stored.source_set_version == 2


def test_non_owner_cannot_update_sources(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only release owner"):
        contract.update_evidence_sources(1, ["https://evil.example"])


@pytest.mark.parametrize(
    "bad_sources",
    [
        TOO_MANY_SOURCES,
        ["ftp://bad"],
        ["not-a-url"],
    ],
)
def test_source_update_rejects_invalid_values(direct_vm, direct_deploy, bad_sources):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert():
        contract.update_evidence_sources(1, bad_sources)


def test_sources_are_rejected_after_first_review(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm)
    review(contract)
    with direct_vm.expect_revert("sources are locked"):
        contract.update_evidence_sources(1, ["https://security.example/new"])


def test_source_version_is_frozen_after_first_review(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm)
    review(contract)
    with direct_vm.expect_revert():
        contract.update_evidence_sources(1, SOURCE_URLS[:1])
    assert get_release(contract).source_set_version == 1


def test_failed_source_update_does_not_increment_version(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert():
        contract.update_evidence_sources(1, [])


def test_policy_and_sources_are_unchanged_after_first_review(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION", release_binding="BOUND")
    review(contract)
    stored = get_release(contract)
    assert stored.review_started is True
    assert stored.release_policy == POLICY
    assert stored.policy_version == 1
    assert list(stored.evidence_sources) == SOURCE_URLS
    assert stored.source_set_version == 1


@pytest.mark.parametrize("urls", [[], REVIEW_URLS + ["https://evidence.example/five"]])
def test_review_rejects_wrong_url_count(direct_vm, direct_deploy, urls):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert():
        review(contract, urls=urls)


@pytest.mark.parametrize(
    "url", ["ftp://evidence.example/bad", "evidence.example/no-scheme"]
)
def test_review_rejects_non_http_urls(direct_vm, direct_deploy, url):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert("HTTP(S)"):
        review(contract, urls=[url])


def test_one_evidence_url_is_valid(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, urls=REVIEW_URLS[:1])
    assert int(review(contract, urls=REVIEW_URLS[:1])) == 1


def test_four_evidence_urls_are_valid(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, urls=REVIEW_URLS)
    assert int(review(contract, urls=REVIEW_URLS)) == 1


@pytest.mark.parametrize("field", ["title", "claimed_risk"])
@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_review_rejects_empty_text_fields(direct_vm, direct_deploy, field, value):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert():
        review(contract, **{field: value})


@pytest.mark.parametrize("status", [200, 404, 500])
def test_http_responses_are_usable_regardless_of_status(
    direct_vm, direct_deploy, status
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, status=status, verdict="CAUTION", summary="HTTP response reviewed")
    review_id = review(contract)
    stored = get_release(contract)
    assert stored.latest_verdict == "CAUTION"
    assert stored.latest_evidence_summary == "HTTP response reviewed"
    assert stored.review_started is True
    assert int(stored.review_count) == 1
    assert stored.latest_release_binding == "BOUND"
    assert stored.blocked is False
    assert get_review(contract, review_id).sequence_number == 1


def test_empty_body_is_usable_evidence(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, body="", verdict="CLEAR")
    review(contract)
    assert get_release(contract).latest_verdict == "CLEAR"


def test_all_transport_failures_return_undetermined_without_llm(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)

    def failing_web(_request):
        raise TimeoutError("transport unavailable")

    direct_vm.clear_mocks()
    direct_vm._live_web_handler = failing_web
    review_id = review(contract)
    stored_review = get_review(contract, review_id)
    assert stored_review.verdict == "UNDETERMINED"
    assert stored_review.release_binding == "UNBOUND"
    assert "transport level" in stored_review.reasoning
    assert stored_review.evidence_summary
    assert get_release(contract).blocked is False
    assert contract.can_release(1) is False


def test_mixed_transport_failure_and_http_response_reaches_llm(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    unavailable = REVIEW_URLS[0]
    available = REVIEW_URLS[1]
    direct_vm.clear_mocks()
    direct_vm.mock_web(
        available, {"method": "GET", "status": 404, "body": "release evidence"}
    )
    direct_vm.mock_llm(
        PROMPT_MARKER,
        {
            "verdict": "CAUTION",
            "release_binding": "PARTIAL",
            "reasoning": "One source was unavailable and the binding is incomplete.",
            "evidence_summary": "One HTTP response and one transport failure.",
        },
    )

    def failing_web(request):
        if request.get("url") == unavailable:
            raise TimeoutError("unavailable")
        return {
            "ok": {
                "response": {
                    "status": 404,
                    "headers": {},
                    "body": b"release evidence",
                }
            }
        }

    direct_vm._live_web_handler = failing_web
    review_id = review(contract, urls=[unavailable, available])
    assert get_review(contract, review_id).verdict == "CAUTION"


def test_evidence_body_is_truncated_before_evaluation(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, body="x" * 12000, verdict="CLEAR", summary="bounded")
    stored_review = get_review(contract, review(contract))
    assert stored_review.evidence_summary == "bounded"


def test_malformed_json_is_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(direct_vm, '{"verdict": "CLEAR"')
    with direct_vm.expect_revert("Malformed verdict JSON"):
        review(contract)
    assert get_release(contract).review_started is False
    assert int(contract.get_review_count()) == 0
    assert get_review(contract, 1) is None


@pytest.mark.parametrize("response", [[], "not-json", 7, True, None])
def test_non_object_llm_results_are_rejected(direct_vm, direct_deploy, response):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(direct_vm, response)
    with direct_vm.expect_revert():
        review(contract)


@pytest.mark.parametrize(
    "missing", ["verdict", "release_binding", "reasoning", "evidence_summary"]
)
def test_missing_required_key_is_rejected(direct_vm, direct_deploy, missing):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    response = {
        "verdict": "CLEAR",
        "release_binding": "BOUND",
        "reasoning": "reason",
        "evidence_summary": "summary",
    }
    del response[missing]
    setup_raw_llm(direct_vm, response)
    with direct_vm.expect_revert():
        review(contract)


@pytest.mark.parametrize(
    "wrong_key", ["verdict", "release_binding", "reasoning", "evidence_summary"]
)
def test_wrong_field_type_is_rejected(direct_vm, direct_deploy, wrong_key):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    response = {
        "verdict": "CLEAR",
        "release_binding": "BOUND",
        "reasoning": "reason",
        "evidence_summary": "summary",
    }
    response[wrong_key] = {"not": "a string"}
    setup_raw_llm(direct_vm, response)
    with direct_vm.expect_revert():
        review(contract)


def test_invalid_verdict_enum_is_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(
        direct_vm,
        {
            "verdict": "SAFE",
            "release_binding": "BOUND",
            "reasoning": "reason",
            "evidence_summary": "summary",
        },
    )
    with direct_vm.expect_revert("Invalid verdict"):
        review(contract)


def test_invalid_release_binding_enum_is_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(
        direct_vm,
        {
            "verdict": "CLEAR",
            "release_binding": "EXACT",
            "reasoning": "reason",
            "evidence_summary": "summary",
        },
    )
    with direct_vm.expect_revert("Invalid release binding"):
        review(contract)


def test_extra_result_key_is_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(
        direct_vm,
        {
            "verdict": "CLEAR",
            "release_binding": "BOUND",
            "reasoning": "reason",
            "evidence_summary": "summary",
            "dangerous_extra": "do not store",
        },
    )
    with direct_vm.expect_revert("object shape"):
        review(contract)
    assert get_release(contract).review_started is False
    assert int(contract.get_review_count()) == 0
    assert get_review(contract, 1) is None


@pytest.mark.parametrize("binding", ["BOUND", "PARTIAL", "UNBOUND"])
def test_strict_verdict_fields_are_stored(direct_vm, direct_deploy, binding):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding=binding, reasoning="r", summary="s")
    review_id = review(contract)
    stored = get_review(contract, review_id)
    assert stored.verdict == "CLEAR"
    assert stored.release_binding == binding
    assert stored.reasoning == "r"
    assert stored.evidence_summary == "s"


def test_bound_clear_authorizes_release(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="BOUND")
    review(contract)
    assert contract.can_release(1) is True


@pytest.mark.parametrize("binding", ["PARTIAL", "UNBOUND"])
def test_weakly_bound_clear_never_authorizes(direct_vm, direct_deploy, binding):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding=binding)
    review(contract)
    assert get_release(contract).latest_verdict == "CLEAR"
    assert get_release(contract).latest_release_binding == binding
    assert contract.can_release(1) is False


def test_generic_or_unrelated_release_evidence_cannot_authorize(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(
        direct_vm,
        verdict="CLEAR",
        release_binding="UNBOUND",
        reasoning="Generic project article, not this version or build.",
    )
    review(contract)
    assert contract.can_release(1) is False


@pytest.mark.parametrize("verdict", ["CAUTION", "UNDETERMINED", "BLOCKED"])
def test_non_clear_verdicts_do_not_authorize(direct_vm, direct_deploy, verdict):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict=verdict, release_binding="BOUND")
    review(contract)
    assert get_release(contract).latest_verdict == verdict
    assert contract.can_release(1) is False


@pytest.mark.parametrize("later_verdict", ["CLEAR", "CAUTION", "UNDETERMINED"])
def test_bound_block_is_sticky_against_later_reviews(
    direct_vm, direct_deploy, later_verdict
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(
        direct_vm,
        verdict="BLOCKED",
        release_binding="BOUND",
        reasoning="Critical exploit in the exact artifact.",
    )
    review(contract)
    assert get_release(contract).blocked is True
    setup(direct_vm, verdict=later_verdict, release_binding="BOUND", body="new evidence packet")
    review(contract)
    assert get_release(contract).latest_verdict == later_verdict
    assert get_release(contract).blocked is True
    assert contract.can_release(1) is False


@pytest.mark.parametrize("binding", ["PARTIAL", "UNBOUND"])
def test_weakly_bound_block_is_downgraded_and_not_sticky(
    direct_vm, direct_deploy, binding
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="BLOCKED", release_binding=binding)
    review_id = review(contract)
    assert get_review(contract, review_id).verdict == "UNDETERMINED"
    assert get_review(contract, review_id).release_binding == binding
    assert get_release(contract).blocked is False


def test_block_remains_after_deactivate_and_reactivate(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="BLOCKED", release_binding="BOUND")
    review(contract)
    contract.set_release_active(1, False)
    contract.set_release_active(1, True)
    assert get_release(contract).blocked is True
    assert get_release(contract).active is True
    assert contract.can_release(1) is False


def test_owner_can_deactivate_and_reactivate_before_block(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    contract.set_release_active(1, False)
    assert get_release(contract).active is False
    contract.set_release_active(1, True)
    assert get_release(contract).active is True


def test_inactive_release_cannot_authorize_after_bound_clear(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="BOUND")
    review(contract)
    contract.set_release_active(1, False)
    assert contract.can_release(1) is False


def test_non_owner_cannot_change_active_state(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only release owner"):
        contract.set_release_active(1, False)


def test_review_does_not_require_owner_signature(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    direct_vm.sender = direct_bob
    setup(direct_vm, verdict="CAUTION", release_binding="BOUND")
    review(contract)
    assert get_release(contract).review_count == 1


def test_review_started_freezes_policy_and_source_snapshot(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION", release_binding="BOUND")
    review(contract)
    stored = get_release(contract)
    assert stored.review_started is True
    assert stored.release_policy == POLICY
    assert stored.policy_version == 1
    assert list(stored.evidence_sources) == SOURCE_URLS
    assert stored.source_set_version == 1


def test_review_count_and_global_review_id_increment(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION")
    first = review(contract)
    setup(direct_vm, verdict="UNDETERMINED", body="second evidence packet")
    second = review(contract)
    assert [int(first), int(second)] == [1, 2]
    assert int(contract.get_review_count()) == 2
    assert [int(get_review(contract, x).sequence_number) for x in [first, second]] == [1, 2]


def test_review_history_is_append_only_and_readable(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION", reasoning="first", summary="first summary")
    first = review(contract, title="First", claimed_risk="first risk")
    setup(direct_vm, verdict="CLEAR", reasoning="second", summary="second summary", body="second evidence packet")
    second = review(contract, title="Second", claimed_risk="second risk")
    assert get_review(contract, first).title == "First"
    assert get_review(contract, first).reasoning == "first"
    assert get_review(contract, second).title == "Second"
    assert get_review(contract, second).reasoning == "second"
    assert get_release(contract).review_count == 2


def test_review_stores_urls_and_sequence(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    urls = REVIEW_URLS[:2]
    setup(direct_vm, urls=urls, verdict="CAUTION")
    review_id = review(contract, urls=urls)
    stored = get_review(contract, review_id)
    assert list(stored.evidence_urls) == urls
    assert int(stored.sequence_number) == 1


def test_review_fields_and_latest_summary_are_persisted(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="BOUND", reasoning="reason", summary="summary")
    review_id = review(contract, title="Title", claimed_risk="Claim")
    stored_review = get_review(contract, review_id)
    stored_release = get_release(contract)
    assert stored_review.title == "Title"
    assert stored_review.claimed_risk == "Claim"
    assert stored_review.verdict == "CLEAR"
    assert stored_review.release_binding == "BOUND"
    assert stored_release.latest_verdict == "CLEAR"
    assert stored_release.latest_release_binding == "BOUND"
    assert stored_release.latest_reasoning == "reason"
    assert stored_release.latest_evidence_summary == "summary"


def test_reviews_for_multiple_releases_have_global_ids_and_independent_sequences(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract, project_name="First")
    register(contract, project_name="Second", artifact_hash="sha256:" + "e" * 64)
    setup(direct_vm, verdict="CLEAR")
    first = review(contract, release_id=1)
    setup(direct_vm, verdict="CAUTION")
    second = review(contract, release_id=2)
    setup(direct_vm, verdict="UNDETERMINED", body="second packet")
    third = review(contract, release_id=1)
    assert [int(first), int(second), int(third)] == [1, 2, 3]
    assert [int(get_review(contract, x).sequence_number) for x in [first, second, third]] == [1, 1, 2]
    assert int(get_release(contract, 1).review_count) == 2
    assert int(get_release(contract, 2).review_count) == 1


def test_missing_release_is_safe_in_views_and_rejected_in_writes(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    assert contract.get_release(999) is None
    assert contract.get_review(999) is None
    assert contract.can_release(999) is False
    with direct_vm.expect_revert("Release not found"):
        contract.set_release_active(999, False)


def test_no_unblock_reset_pardon_or_clear_surface_exists(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    forbidden = ["unblock_release", "reset_release", "pardon_release", "clear_blocked"]
    assert all(not hasattr(contract, name) for name in forbidden)


def test_new_artifact_requires_new_release_record(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="BLOCKED", release_binding="BOUND")
    review(contract)
    new_release = register(contract, artifact_hash="sha256:" + "e" * 64)
    assert int(new_release) == 2
    assert get_release(contract, 1).blocked is True
    assert get_release(contract, 2).blocked is False
    assert get_release(contract, 2).artifact_hash != get_release(contract, 1).artifact_hash


def test_blocked_release_stays_blocked_after_favorable_unbound_filing(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="BLOCKED", release_binding="BOUND")
    review(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="UNBOUND", body="new packet, but unbound")
    review(contract)
    assert get_release(contract).blocked is True
    assert contract.can_release(1) is False


def test_identity_policy_and_source_snapshots_remain_recorded_after_review(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="PARTIAL")
    review(contract)
    stored = get_release(contract)
    assert stored.commit_hash == COMMIT
    assert stored.artifact_hash == ARTIFACT
    assert stored.manifest_hash == MANIFEST
    assert stored.sbom_hash == SBOM
    assert stored.release_policy == POLICY
    assert stored.policy_version == 1
    assert stored.source_set_version == 1


def test_authorized_release_can_be_disabled_and_reenabled_without_block(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="BOUND")
    review(contract)
    assert contract.can_release(1) is True
    contract.set_release_active(1, False)
    assert contract.can_release(1) is False
    contract.set_release_active(1, True)
    assert contract.can_release(1) is True


def test_latest_verdict_changes_but_history_remains(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION")
    first = review(contract)
    setup(direct_vm, verdict="CLEAR", release_binding="BOUND", body="second packet")
    second = review(contract)
    assert get_release(contract).latest_verdict == "CLEAR"
    assert get_release(contract).review_count == 2
    assert get_review(contract, first).verdict == "CAUTION"
    assert get_review(contract, second).verdict == "CLEAR"


def test_undetermined_after_block_cannot_restore_authorization(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="BLOCKED", release_binding="BOUND")
    review(contract)
    setup(direct_vm, verdict="UNDETERMINED", release_binding="UNBOUND", body="second evidence packet")
    review(contract)
    assert get_release(contract).blocked is True
    assert get_release(contract).latest_verdict == "UNDETERMINED"
    assert contract.can_release(1) is False


def test_bound_caution_is_readable_but_not_authorized(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION", release_binding="BOUND")
    review_id = review(contract)
    assert get_review(contract, review_id).verdict == "CAUTION"
    assert contract.can_release(1) is False


def test_bound_undetermined_is_readable_but_not_authorized(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="UNDETERMINED", release_binding="BOUND")
    review_id = review(contract)
    assert get_review(contract, review_id).verdict == "UNDETERMINED"
    assert contract.can_release(1) is False


def test_blocked_release_cannot_authorize_even_if_reactivated(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="BLOCKED", release_binding="BOUND")
    review(contract)
    contract.set_release_active(1, False)
    contract.set_release_active(1, True)
    assert contract.can_release(1) is False

def test_configured_source_is_accepted_exactly(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, urls=[REVIEW_URLS[0]])
    assert review(contract, urls=[REVIEW_URLS[0]]) == 1


@pytest.mark.parametrize(
    "urls",
    [
        ["https://unregistered.example/advisory"],
        [REVIEW_URLS[0], "https://unregistered.example/advisory"],
    ],
)
def test_unconfigured_or_mixed_sources_are_rejected(direct_vm, direct_deploy, urls):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert("not in the frozen source set"):
        review(contract, urls=urls)


@pytest.mark.parametrize(
    "url",
    [
        "https://evidence.example/advisory/",
        "https://EVIDENCE.example/advisory",
        "https://evidence.example/advisory?copy=1",
    ],
)
def test_alternate_source_spelling_cannot_bypass_exact_membership(
    direct_vm, direct_deploy, url
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert("not in the frozen source set"):
        review(contract, urls=[url])


def test_fourteen_configured_sources_are_stored_and_reviewable(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    sources = TOO_MANY_SOURCES[:14]
    register(contract, evidence_sources=sources)
    setup(direct_vm, urls=sources[:1])
    review_id = review(contract, urls=sources[:1])
    assert list(get_release(contract).evidence_sources) == sources
    assert list(get_review(contract, review_id).evidence_urls) == sources[:1]


def test_policy_version_is_system_controlled_and_monotonic(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    assert get_release(contract).policy_version == 1
    contract.update_release_policy(1, "Stricter policy")
    assert get_release(contract).policy_version == 2
    contract.update_release_policy(1, "Strictest policy")
    assert get_release(contract).policy_version == 3


def test_source_version_is_system_controlled_and_monotonic(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    assert get_release(contract).source_set_version == 1
    replacement = [REVIEW_URLS[0]]
    contract.update_evidence_sources(1, replacement)
    assert get_release(contract).source_set_version == 2
    contract.update_evidence_sources(1, SOURCE_URLS[:2])
    assert get_release(contract).source_set_version == 3


def test_review_snapshots_current_policy_and_source_versions(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    contract.update_release_policy(1, "Updated policy")
    contract.update_evidence_sources(1, SOURCE_URLS[:2])
    setup(direct_vm, urls=SOURCE_URLS[:1])
    review_id = review(contract, urls=SOURCE_URLS[:1])
    stored = get_review(contract, review_id)
    assert stored.policy_version == 2
    assert stored.source_set_version == 2
    assert get_release(contract).policy_version == 2
    assert get_release(contract).source_set_version == 2


def test_legacy_caller_supplied_version_arguments_are_not_accepted(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    with pytest.raises(TypeError):
        contract.register_release(
            PROJECT,
            VERSION,
            COMMIT,
            ARTIFACT,
            MANIFEST,
            SBOM,
            POLICY,
            "caller-policy-version",
            SOURCE_URLS,
            "caller-source-version",
        )


def test_same_evidence_packet_cannot_be_replayed(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION")
    first = review(contract)
    with direct_vm.expect_revert("already reviewed"):
        review(contract)
    assert first == 1
    assert int(contract.get_review_count()) == 1


def test_review_commitment_is_stored_and_new_packet_is_allowed(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION")
    first = review(contract)
    setup(direct_vm, verdict="CAUTION", body="materially different evidence")
    second = review(contract)
    first_review = get_review(contract, first)
    second_review = get_review(contract, second)
    assert len(first_review.evidence_commitment) == 64
    assert len(second_review.evidence_commitment) == 64
    assert first_review.evidence_commitment != second_review.evidence_commitment

def test_review_commitment_covers_sbom_identity(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    module = sys.modules[type(contract).__module__]
    evidence = [{"url": REVIEW_URLS[0], "status": 200, "body": "release evidence"}]
    common = [
        "1",
        PROJECT,
        VERSION,
        COMMIT,
        ARTIFACT,
        MANIFEST,
        1,
        1,
        SOURCE_URLS,
        REVIEW_URLS[:1],
        evidence,
    ]
    first = module._evidence_commitment(*common[:6], SBOM, *common[6:])
    second = module._evidence_commitment(
        *common[:6], "sha256:" + "e" * 64, *common[6:]
    )
    assert first != second


def test_review_snapshots_are_independent_of_later_failed_mutations(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup(direct_vm, verdict="CAUTION")
    review_id = review(contract)
    stored = get_review(contract, review_id)
    with direct_vm.expect_revert():
        contract.update_release_policy(1, "later")
    with direct_vm.expect_revert():
        contract.update_evidence_sources(1, [REVIEW_URLS[1]])
    assert stored.policy_version == 1
    assert stored.source_set_version == 1


def test_malformed_result_does_not_start_review(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(direct_vm, '{"verdict": "CLEAR"')
    with direct_vm.expect_revert("Malformed verdict JSON"):
        review(contract)
    assert get_release(contract).review_started is False
    assert int(contract.get_review_count()) == 0
    assert get_review(contract, 1) is None
    contract.update_release_policy(1, "Retry policy")
    contract.update_evidence_sources(1, [REVIEW_URLS[1]])
    stored = get_release(contract)
    assert stored.review_started is False
    assert stored.release_policy == "Retry policy"
    assert stored.policy_version == 2
    assert list(stored.evidence_sources) == [REVIEW_URLS[1]]
    assert stored.source_set_version == 2

def test_nondeterministic_evaluation_exception_does_not_start_review(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    direct_vm.clear_mocks()
    direct_vm.mock_web(
        REVIEW_URLS[0],
        {"method": "GET", "status": 200, "body": "release evidence"},
    )

    def failing_llm(_request):
        raise RuntimeError("evaluation failed")

    direct_vm._live_llm_handler = failing_llm
    with direct_vm.expect_revert():
        review(contract)
    assert get_release(contract).review_started is False
    assert int(contract.get_review_count()) == 0
    assert get_review(contract, 1) is None


def test_zero_usable_evidence_has_commitment_and_never_calls_llm(
    direct_vm, direct_deploy
):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    direct_vm.clear_mocks()

    def failing_web(_request):
        raise TimeoutError("transport unavailable")

    direct_vm._live_web_handler = failing_web
    review_id = review(contract)
    stored = get_review(contract, review_id)
    assert stored.verdict == "UNDETERMINED"
    assert len(stored.evidence_commitment) == 64
    assert get_release(contract).blocked is False
    assert contract.can_release(1) is False


def test_duplicate_review_urls_are_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    with direct_vm.expect_revert("duplicates"):
        review(contract, urls=[REVIEW_URLS[0], REVIEW_URLS[0]])


def test_url_order_cannot_grind_same_evidence_packet(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    urls = REVIEW_URLS[:2]
    setup(direct_vm, urls=urls, verdict="CAUTION")
    review(contract, urls=urls)
    setup(direct_vm, urls=list(reversed(urls)), verdict="CLEAR")
    with direct_vm.expect_revert("already reviewed"):
        review(contract, urls=list(reversed(urls)))


def test_null_verdict_field_is_rejected(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    register(contract)
    setup_raw_llm(
        direct_vm,
        {
            "verdict": None,
            "release_binding": "BOUND",
            "reasoning": "reason",
            "evidence_summary": "summary",
        },
    )
    with direct_vm.expect_revert("fields must be strings"):
        review(contract)


def test_release_signer_and_identity_survive_permissionless_reviews(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_vm, direct_deploy)
    direct_vm.sender = direct_alice
    register(contract)
    owner = get_release(contract).release_signer
    direct_vm.sender = direct_bob
    setup(direct_vm, verdict="CAUTION")
    review(contract)
    stored = get_release(contract)
    assert stored.release_signer == owner
    assert stored.project_name == PROJECT
    assert stored.version == VERSION
    assert stored.commit_hash == COMMIT
    assert stored.artifact_hash == ARTIFACT
    assert stored.manifest_hash == MANIFEST
    assert stored.sbom_hash == SBOM
