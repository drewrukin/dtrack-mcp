"""Input validation for dtrack-mcp tools.

Layer 1 — unknown kwargs → TypeError.  Active for direct Python callers.
FastMCP pre-filters kwargs via its Pydantic arg model (extra="ignore"),
so this layer does not fire for LLM-originated calls.  The LLM-facing
Layer 1 guard is additionalProperties: false in the JSON schema — see
seal_schemas().

Layer 2 — enum validation → ValueError.  Active for all callers because
FastMCP binds declared enum params correctly before calling the wrapper.
"""
from __future__ import annotations

import inspect
from functools import wraps
from typing import Any

_ANALYSIS_STATES: frozenset[str] = frozenset({
    "NOT_SET", "IN_TRIAGE", "EXPLOITABLE",
    "FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED",
})
_SEVERITIES: frozenset[str] = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED",
})
_JUSTIFICATIONS: frozenset[str] = frozenset({
    "CODE_NOT_PRESENT", "CODE_NOT_REACHABLE", "REQUIRES_CONFIGURATION",
    "REQUIRES_DEPENDENCY", "REQUIRES_ENVIRONMENT", "PROTECTED_BY_COMPILER",
    "PROTECTED_AT_RUNTIME", "PROTECTED_AT_PERIMETER",
    "PROTECTED_BY_MITIGATING_CONTROL",
})
_RESPONSES: frozenset[str] = frozenset({
    "CAN_NOT_FIX", "WILL_NOT_FIX", "UPDATE", "ROLLBACK", "WORKAROUND_AVAILABLE",
})

_ENUMS: dict[str, frozenset[str]] = {
    "analysis_states": _ANALYSIS_STATES,   # list_findings, group_findings_by_alias
    "severities":      _SEVERITIES,        # list_findings, group_findings_by_alias
    "states":          _ANALYSIS_STATES,   # find_duplicate_analyses
    "state":           _ANALYSIS_STATES,   # set_analysis, set_analysis_for_finding
    "mode":            frozenset({"dry_run", "exact"}),  # carry_over_triage
    "justification":   _JUSTIFICATIONS,    # set_analysis, set_analysis_for_finding
    "response":        _RESPONSES,         # set_analysis, set_analysis_for_finding
}


def validated(fn: Any) -> Any:
    """Wrap a tool function with Layer 1 (unknown kwargs) + Layer 2 (enum) validation."""
    allowed = frozenset(inspect.signature(fn).parameters)

    @wraps(fn)
    def wrapper(**kw: Any) -> Any:
        extra = set(kw) - allowed
        if extra:
            raise TypeError(
                f"Unknown params: {sorted(extra)}; allowed: {sorted(allowed)}"
            )
        for name, value in kw.items():
            if name not in _ENUMS or value is None:
                continue
            items = value if isinstance(value, list) else [value]
            bad = [x for x in items if x not in _ENUMS[name]]
            if bad:
                raise ValueError(
                    f"{name}: invalid value(s) {sorted(bad)}; "
                    f"allowed: {sorted(_ENUMS[name])}"
                )
        return fn(**kw)

    return wrapper


def seal_schemas(mcp_server: Any) -> None:
    """Add additionalProperties: false to every registered tool's JSON schema.

    Call once after all @mcp.tool() registrations.  This is the LLM-facing
    Layer 1 guard: compliant MCP clients will not propose parameter names
    that are absent from the schema.
    """
    for tool in mcp_server._tool_manager.list_tools():
        tool.parameters.setdefault("additionalProperties", False)
