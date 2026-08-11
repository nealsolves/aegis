"""Custom PolicyLoaderBase subclasses for the AEGIS demo API.

These loaders demonstrate the pluggable loader architecture that ships in the
current AEGIS SDK. Pass a loader instance to AEGIS(policy_loader=...) to control
how policies are resolved — no filesystem path required.
"""

import copy

from aegis import PolicyLoaderBase

from bounded_yaml import load_bounded_yaml


class InMemoryPolicyLoader(PolicyLoaderBase):
    """Holds a single policy dict loaded from a raw YAML string.

    Demonstrates pluggable loader architecture: the policy source is
    arbitrary YAML text rather than a file path. The SDK calls
    ``load(policy_ref)`` transparently — the caller never touches the disk.

    Usage::

        loader = InMemoryPolicyLoader(yaml_text)
        aegis = AEGIS(policy_loader=loader)
        artifact = aegis.enforce(invocation)
    """

    def __init__(self, yaml_text: str) -> None:
        self._policy = load_bounded_yaml(yaml_text)

    def load(self, policy_ref: str) -> dict:  # noqa: ARG002
        return copy.deepcopy(self._policy)
