class ReleaseBlocked(Exception):
    """Raised when a release is not currently authorized or authorization failed."""


class ReleaseExecutionFailed(Exception):
    """Raised when an authorized downstream deployment fails."""


class PatchLockReleaseGate:
    """Reference fail-closed deployment boundary for PatchLock."""

    def __init__(self, authorization_source):
        self.authorization = authorization_source

    def execute(self, release_id, deployment_target, payload):
        try:
            allowed = bool(self.authorization.can_release(release_id))
        except Exception as exc:
            raise ReleaseBlocked(release_id) from exc
        if not allowed:
            raise ReleaseBlocked(release_id)
        try:
            return deployment_target.deploy(payload)
        except Exception as exc:
            raise ReleaseExecutionFailed(release_id) from exc
