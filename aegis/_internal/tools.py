"""
Tool constraint validation.

Enforces allowlists and per-tool call limits from policy.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from aegis._internal.compiled_policy import CompiledToolPolicy
from aegis._internal.errors import ToolConstraintViolationError


def validate_tool_constraints(
    invocation: Mapping[str, Any],
    tools: CompiledToolPolicy,
) -> dict[str, Any]:
    """
    Validate tool usage against policy constraints.

    :param invocation: Invocation dict with optional "tool_calls" field
    :param tools: Immutable compiled tool limits.
    :return: Dict with validation summary for audit

    Validation rules:
    - If no "tools" in policy, skip validation
    - If no "tool_calls" in invocation, skip validation
    - Each tool must be in allowed_tools list
    - Each tool's call count must be <= max_calls

    Returns:
        {
            "tools_checked": ["search", "analyze"],
            "violations": []  # or list of violation dicts
        }
    """
    tool_calls = invocation.get("tool_calls")
    if not tool_calls:
        return {"tools_checked": [], "violations": []}

    if not isinstance(tools, CompiledToolPolicy):
        raise TypeError("tools must be a CompiledToolPolicy")

    # An absent tools declaration preserves the documented unconfigured
    # behavior. A configured empty declaration is a deny-all allowlist.
    if not tools.configured:
        return {"tools_checked": [], "violations": []}

    tool_limits = {
        tool.name: tool.max_calls
        for tool in tools.allowed_tools
    }

    # Count actual calls per tool
    call_counts = Counter(tc["name"] for tc in tool_calls)
    tools_checked = list(call_counts.keys())
    violations: list[dict[str, Any]] = []

    for tool_name, count in call_counts.items():
        # Check allowlist
        if tool_name not in tool_limits:
            raise ToolConstraintViolationError(
                f"Tool '{tool_name}' not in allowed_tools list",
                details={
                    "tool": tool_name,
                    "allowed_tools": list(tool_limits.keys()),
                },
            )

        # Check max_calls
        max_calls = tool_limits[tool_name]
        if count > max_calls:
            raise ToolConstraintViolationError(
                f"Tool '{tool_name}' called {count} times, max is {max_calls}",
                details={
                    "tool": tool_name,
                    "actual_calls": count,
                    "max_calls": max_calls,
                },
            )

    return {
        "tools_checked": sorted(tools_checked),
        "violations": violations,
    }
