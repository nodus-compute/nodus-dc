"""Execution privacy requirements, independent of allocation and encryption."""

from .errors import Error


REQUIREMENTS = ("trusted_host", "host_confidential")


def capabilities():
    """Software guarantees only; inventory labels cannot attest a runtime."""
    return {"supported_requirements": ["trusted_host"],
            "host_operator_may_access_workload": True,
            "confidential_execution": {"available": False,
                                       "reason": "attested_execution_unavailable"}}


def require(value):
    if not isinstance(value, str) or value not in REQUIREMENTS:
        raise Error("invalid_privacy_requirement",
                    "required_privacy must be trusted_host or host_confidential", 400)
    if value == "host_confidential":
        raise Error("privacy_unavailable",
                    "host-confidential execution requires an attested CPU/GPU runtime and verified key release; "
                    "this backend trusts the host operator", 409)
