"""Root-bound AEGIS construction for server-owned demo policies."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis import (
    AEGIS,
    AuditSink,
    CallbackAuditSink,
    FilePolicyLoader,
    JsonFileAuditSink,
)


def _owned_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    if "sink" in kwargs or "policy_loader" in kwargs:
        raise TypeError("demo runtime owns sink and policy_loader")
    return kwargs


def demo_aegis(policy_root: str | Path, **kwargs: Any) -> AEGIS:
    """Create an engine with one fixed filesystem authority and discard sink."""

    return AEGIS(
        sink=CallbackAuditSink(lambda _artifact: None),
        policy_loader=FilePolicyLoader(policy_root),
        **_owned_kwargs(kwargs),
    )


def demo_aegis_with_sink(
    policy_root: str | Path,
    sink: AuditSink,
    **kwargs: Any,
) -> AEGIS:
    """Create a root-bound engine for routes that intentionally retain evidence."""

    return AEGIS(
        sink=sink,
        policy_loader=FilePolicyLoader(policy_root),
        **_owned_kwargs(kwargs),
    )


def logical_policy_ref(policy_root: str | Path, policy_path: str | Path) -> str:
    """Return a POSIX logical reference only for a canonically contained file."""

    root = Path(policy_root).resolve(strict=True)
    candidate = Path(policy_path).resolve(strict=True)
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        raise ValueError("policy is outside the demo policy root") from None
    return relative.as_posix()


@dataclass(frozen=True, slots=True)
class _DemoStarterSinkIntent:
    path: Path


class DemoAegisModuleProxy:
    """Module-local proxy that replaces only generated code's AEGIS factory."""

    def __init__(self, original_module: Any, policy_root: str | Path) -> None:
        self._original_module = original_module
        self._policy_root = Path(policy_root).resolve(strict=True)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original_module, name)

    def JsonFileAuditSink(self, path: str | Path) -> _DemoStarterSinkIntent:
        candidate = Path(path).resolve(strict=False)
        try:
            candidate.relative_to(self._policy_root)
        except ValueError:
            raise ValueError("sink is outside the demo policy root") from None
        return _DemoStarterSinkIntent(candidate)

    def AEGIS(self, *args: Any, **kwargs: Any) -> AEGIS:
        if args:
            raise TypeError("AEGIS accepts keyword arguments only")
        protected = set(kwargs) & {"policy_loader", "signer", "chain_linker"}
        if protected:
            raise TypeError(
                f"demo runtime owns protected AEGIS authority: {sorted(protected)[0]}"
            )
        unknown = set(kwargs) - {"sink", "custom_gates"}
        if unknown:
            raise TypeError(f"unsupported AEGIS option: {sorted(unknown)[0]}")
        sink_intent = kwargs.pop("sink", None)
        if sink_intent is None:
            return demo_aegis(self._policy_root, **kwargs)
        if type(sink_intent) is not _DemoStarterSinkIntent:
            raise TypeError("demo workflow requires a root-bound starter sink")
        return demo_aegis_with_sink(
            self._policy_root,
            JsonFileAuditSink(sink_intent.path),
            **kwargs,
        )
