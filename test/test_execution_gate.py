import pytest

from execution.patchlock_release_gate import (
    PatchLockReleaseGate,
    ReleaseBlocked,
    ReleaseExecutionFailed,
)


class Authorization:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = 0

    def can_release(self, release_id):
        self.calls += 1
        return next(self.values)


class DeploymentTarget:
    def __init__(self, result="deployed"):
        self.result = result
        self.payloads = []

    def deploy(self, payload):
        self.payloads.append(payload)
        return self.result


def test_false_authorization_blocks_target():
    target = DeploymentTarget()
    with pytest.raises(ReleaseBlocked):
        PatchLockReleaseGate(Authorization([False])).execute(1, target, {"x": 1})
    assert target.payloads == []


def test_authorization_exception_fails_closed():
    class BrokenAuthorization:
        def can_release(self, _release_id):
            raise RuntimeError("read failed")

    target = DeploymentTarget()
    with pytest.raises(ReleaseBlocked):
        PatchLockReleaseGate(BrokenAuthorization()).execute(1, target, {})
    assert target.payloads == []


def test_true_authorization_forwards_exact_payload_and_result():
    payload = {"nested": [1, {"key": "value"}]}
    result = object()
    target = DeploymentTarget(result)
    assert PatchLockReleaseGate(Authorization([True])).execute(7, target, payload) is result
    assert target.payloads[0] is payload


def test_target_exception_is_wrapped_separately():
    class BrokenTarget:
        def deploy(self, _payload):
            raise ValueError("downstream failure")

    with pytest.raises(ReleaseExecutionFailed):
        PatchLockReleaseGate(Authorization([True])).execute(9, BrokenTarget(), "payload")


def test_authorization_is_reread_on_every_call():
    authorization = Authorization([True, True])
    target = DeploymentTarget()
    gate = PatchLockReleaseGate(authorization)
    gate.execute(3, target, "one")
    gate.execute(3, target, "two")
    assert authorization.calls == 2
    assert target.payloads == ["one", "two"]


def test_true_to_false_transition_blocks_second_call():
    authorization = Authorization([True, False])
    target = DeploymentTarget()
    gate = PatchLockReleaseGate(authorization)
    gate.execute(3, target, "first")
    with pytest.raises(ReleaseBlocked):
        gate.execute(3, target, "second")
    assert target.payloads == ["first"]


def test_false_to_true_transition_allows_later_call():
    authorization = Authorization([False, True])
    target = DeploymentTarget()
    gate = PatchLockReleaseGate(authorization)
    with pytest.raises(ReleaseBlocked):
        gate.execute(3, target, "blocked")
    assert gate.execute(3, target, "allowed") == "deployed"
    assert target.payloads == ["allowed"]


def test_false_deployment_result_is_forwarded():
    target = DeploymentTarget(False)
    assert PatchLockReleaseGate(Authorization([True])).execute(3, target, "payload") is False


def test_gate_has_no_authorization_cache():
    gate = PatchLockReleaseGate(Authorization([True]))
    assert not hasattr(gate, "_cache")
    assert not hasattr(gate, "_authorized")


@pytest.mark.parametrize("release_id", [1, "release-v1", ("release", 1)])
def test_release_id_is_forwarded_to_authorization(release_id):
    authorization = Authorization([False])
    with pytest.raises(ReleaseBlocked):
        PatchLockReleaseGate(authorization).execute(
            release_id, DeploymentTarget(), "payload"
        )
    assert authorization.calls == 1


def test_target_is_not_called_when_authorization_returns_falsy_non_bool():
    target = DeploymentTarget()
    with pytest.raises(ReleaseBlocked):
        PatchLockReleaseGate(Authorization([None])).execute(1, target, "payload")
    assert target.payloads == []


@pytest.mark.parametrize("state", ["inactive", "blocked", "clear-but-non-bound"])
def test_inactive_blocked_and_non_bound_states_fail_closed(state):
    target = DeploymentTarget()
    with pytest.raises(ReleaseBlocked):
        PatchLockReleaseGate(Authorization([False])).execute(
            state, target, {"state": state}
        )
    assert target.payloads == []
