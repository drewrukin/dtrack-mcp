"""Tests for dtrack_mcp.validation — Layer 1 (unknown kwargs) + Layer 2 (enums).

Layer 1 tests confirm that the @validated wrapper raises TypeError when an
unknown kwarg is passed directly (Python-level protection).  FastMCP drops
unknown kwargs before calling the wrapper for LLM-originated calls, so
Layer 1 is not exercisable through the MCP protocol — the LLM-facing guard
is additionalProperties: false in the JSON schema (see seal_schemas tests).

Layer 2 tests confirm that invalid enum values raise ValueError with a
message that names the param, the bad value(s), and the allowed set.
"""
from __future__ import annotations

import pytest

from dtrack_mcp.validation import (
    _ANALYSIS_STATES,
    _JUSTIFICATIONS,
    _RESPONSES,
    _SEVERITIES,
    seal_schemas,
    validated,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fn(**defaults):
    """Return a @validated function whose params match the provided defaults."""
    src_params = ", ".join(
        f"{k}={v!r}" if v is not None else f"{k}=None"
        for k, v in defaults.items()
    )

    exec_globals: dict = {}
    exec(
        f"def _fn({src_params}): return dict({', '.join(f'{k}={k}' for k in defaults)})",
        exec_globals,
    )
    return validated(exec_globals["_fn"])


# ---------------------------------------------------------------------------
# Layer 1 — unknown kwargs
# ---------------------------------------------------------------------------


def _simple():
    """A minimal @validated function for Layer 1 tests."""
    def fn(project_uuid: str, page: int = 1) -> dict:
        return {"project_uuid": project_uuid, "page": page}
    return validated(fn)


class TestLayer1:
    def test_unknown_kwarg_raises_type_error(self):
        fn = _simple()
        with pytest.raises(TypeError, match="Unknown params"):
            fn(project_uuid="abc", page=1, only_not_set=True)

    def test_unknown_kwarg_message_contains_bad_key(self):
        fn = _simple()
        with pytest.raises(TypeError, match="only_not_set"):
            fn(project_uuid="abc", only_not_set=True)

    def test_unknown_kwarg_message_contains_allowed(self):
        fn = _simple()
        with pytest.raises(TypeError, match="allowed"):
            fn(project_uuid="abc", ghost=1)

    def test_multiple_unknown_kwargs(self):
        fn = _simple()
        with pytest.raises(TypeError, match="Unknown params"):
            fn(project_uuid="abc", foo=1, bar=2)

    def test_known_kwargs_pass(self):
        fn = _simple()
        result = fn(project_uuid="abc", page=2)
        assert result == {"project_uuid": "abc", "page": 2}

    def test_defaults_work(self):
        fn = _simple()
        result = fn(project_uuid="x")
        assert result["page"] == 1


# ---------------------------------------------------------------------------
# Layer 2 — enum validation
# ---------------------------------------------------------------------------


def _make_enum_fn(param: str, default=None):
    """Return @validated function with one enum param."""
    def fn(**kw):
        return kw

    import inspect
    from functools import wraps

    sig_str = f"{param}=None" if default is None else f"{param}={default!r}"
    exec_globals: dict = {}
    exec(
        f"def _fn({sig_str}): return {{'{param}': {param}}}",
        exec_globals,
    )
    return validated(exec_globals["_fn"])


class TestLayer2Severities:
    @pytest.mark.parametrize("good", sorted(_SEVERITIES))
    def test_valid_severity_passes(self, good: str):
        fn = _make_enum_fn("severities")
        assert fn(severities=[good]) == {"severities": [good]}

    def test_invalid_severity_raises(self):
        fn = _make_enum_fn("severities")
        with pytest.raises(ValueError, match="severities"):
            fn(severities=["CRITICAL", "BOGUS"])

    def test_invalid_severity_message_contains_value(self):
        fn = _make_enum_fn("severities")
        with pytest.raises(ValueError, match="BOGUS"):
            fn(severities=["BOGUS"])

    def test_none_passes(self):
        fn = _make_enum_fn("severities")
        assert fn(severities=None) == {"severities": None}

    def test_empty_list_passes(self):
        fn = _make_enum_fn("severities")
        assert fn(severities=[]) == {"severities": []}


class TestLayer2AnalysisStates:
    @pytest.mark.parametrize("good", sorted(_ANALYSIS_STATES))
    def test_valid_state_passes_as_list(self, good: str):
        fn = _make_enum_fn("analysis_states")
        assert fn(analysis_states=[good]) == {"analysis_states": [good]}

    def test_invalid_state_raises(self):
        fn = _make_enum_fn("analysis_states")
        with pytest.raises(ValueError, match="analysis_states"):
            fn(analysis_states=["NOT_SET", "MADE_UP"])

    def test_none_passes(self):
        fn = _make_enum_fn("analysis_states")
        assert fn(analysis_states=None) == {"analysis_states": None}


class TestLayer2States:
    """find_duplicate_analyses uses 'states' (not 'analysis_states')."""

    @pytest.mark.parametrize("good", sorted(_ANALYSIS_STATES))
    def test_valid_state_passes(self, good: str):
        fn = _make_enum_fn("states")
        assert fn(states=[good]) == {"states": [good]}

    def test_invalid_raises(self):
        fn = _make_enum_fn("states")
        with pytest.raises(ValueError, match="states"):
            fn(states=["INVALID_STATE"])


class TestLayer2State:
    """set_analysis uses scalar 'state'."""

    @pytest.mark.parametrize("good", sorted(_ANALYSIS_STATES))
    def test_valid_scalar_passes(self, good: str):
        fn = _make_enum_fn("state")
        assert fn(state=good) == {"state": good}

    def test_invalid_scalar_raises(self):
        fn = _make_enum_fn("state")
        with pytest.raises(ValueError, match="state"):
            fn(state="WRONG")

    def test_message_lists_allowed(self):
        fn = _make_enum_fn("state")
        with pytest.raises(ValueError, match="allowed"):
            fn(state="WRONG")


class TestLayer2Mode:
    @pytest.mark.parametrize("good", ["dry_run", "exact"])
    def test_valid_mode_passes(self, good: str):
        fn = _make_enum_fn("mode", default="dry_run")
        assert fn(mode=good) == {"mode": good}

    def test_invalid_mode_raises(self):
        fn = _make_enum_fn("mode", default="dry_run")
        with pytest.raises(ValueError, match="mode"):
            fn(mode="live")

    def test_none_passes(self):
        fn = _make_enum_fn("mode")
        assert fn(mode=None) == {"mode": None}


class TestLayer2Justification:
    @pytest.mark.parametrize("good", sorted(_JUSTIFICATIONS))
    def test_valid_justification_passes(self, good: str):
        fn = _make_enum_fn("justification")
        assert fn(justification=good) == {"justification": good}

    def test_invalid_justification_raises(self):
        fn = _make_enum_fn("justification")
        with pytest.raises(ValueError, match="justification"):
            fn(justification="NOT_A_REASON")

    def test_none_passes(self):
        fn = _make_enum_fn("justification")
        assert fn(justification=None) == {"justification": None}


class TestLayer2Response:
    @pytest.mark.parametrize("good", sorted(_RESPONSES))
    def test_valid_response_passes(self, good: str):
        fn = _make_enum_fn("response")
        assert fn(response=good) == {"response": good}

    def test_invalid_response_raises(self):
        fn = _make_enum_fn("response")
        with pytest.raises(ValueError, match="response"):
            fn(response="PATCH")

    def test_none_passes(self):
        fn = _make_enum_fn("response")
        assert fn(response=None) == {"response": None}


# ---------------------------------------------------------------------------
# seal_schemas
# ---------------------------------------------------------------------------


class TestSealSchemas:
    def test_seal_adds_additional_properties_false(self):
        from mcp.server.fastmcp import FastMCP

        test_mcp = FastMCP("test")

        @test_mcp.tool()
        @validated
        def dummy(project_uuid: str, page: int = 1) -> dict:
            return {}

        seal_schemas(test_mcp)
        tool = test_mcp._tool_manager.get_tool("dummy")
        assert tool is not None
        assert tool.parameters.get("additionalProperties") is False

    def test_seal_does_not_overwrite_existing(self):
        from mcp.server.fastmcp import FastMCP

        test_mcp = FastMCP("test2")

        @test_mcp.tool()
        @validated
        def dummy2(x: str) -> dict:
            return {}

        tool = test_mcp._tool_manager.get_tool("dummy2")
        assert tool is not None
        tool.parameters["additionalProperties"] = True  # pre-set
        seal_schemas(test_mcp)
        # setdefault should not overwrite an existing value
        assert tool.parameters["additionalProperties"] is True


# ---------------------------------------------------------------------------
# @validated preserves function metadata
# ---------------------------------------------------------------------------


class TestDecoratorMetadata:
    def test_name_preserved(self):
        def my_tool(x: int) -> int:
            return x

        wrapped = validated(my_tool)
        assert wrapped.__name__ == "my_tool"

    def test_doc_preserved(self):
        def my_tool(x: int) -> int:
            """My docstring."""
            return x

        wrapped = validated(my_tool)
        assert wrapped.__doc__ == "My docstring."

    def test_wrapped_attribute_set(self):
        def my_tool(x: int) -> int:
            return x

        wrapped = validated(my_tool)
        assert wrapped.__wrapped__ is my_tool


# ---------------------------------------------------------------------------
# Integration: @validated on realistic tool signatures from server.py
# ---------------------------------------------------------------------------


class TestRealisticSignatures:
    """Smoke-tests against exact parameter names used in server.py."""

    def _make_list_findings(self):
        def list_findings(
            project_uuid: str,
            suppressed: bool = False,
            analysis_states: list | None = None,
            severities: list | None = None,
            page: int = 1,
            page_size: int = 100,
            include_details: bool = False,
        ) -> dict:
            return {}

        return validated(list_findings)

    def test_list_findings_valid(self):
        fn = self._make_list_findings()
        fn(
            project_uuid="abc",
            analysis_states=["NOT_SET", "IN_TRIAGE"],
            severities=["HIGH", "CRITICAL"],
        )

    def test_list_findings_bad_severity(self):
        fn = self._make_list_findings()
        with pytest.raises(ValueError, match="severities"):
            fn(project_uuid="abc", severities=["EXTREME"])

    def test_list_findings_bad_analysis_state(self):
        fn = self._make_list_findings()
        with pytest.raises(ValueError, match="analysis_states"):
            fn(project_uuid="abc", analysis_states=["DEFINITELY_NOT"])

    def test_list_findings_unknown_kwarg(self):
        fn = self._make_list_findings()
        with pytest.raises(TypeError, match="only_not_set"):
            fn(project_uuid="abc", only_not_set=True)

    def _make_set_analysis(self):
        def set_analysis(
            project_uuid: str,
            component_uuid: str,
            vulnerability_uuid: str,
            state: str,
            justification: str | None = None,
            response: str | None = None,
            details: str | None = None,
            comment: str | None = None,
            suppressed: bool | None = None,
        ) -> dict:
            return {}

        return validated(set_analysis)

    def test_set_analysis_valid(self):
        fn = self._make_set_analysis()
        fn(
            project_uuid="p",
            component_uuid="c",
            vulnerability_uuid="v",
            state="NOT_AFFECTED",
            justification="CODE_NOT_REACHABLE",
            response="WILL_NOT_FIX",
        )

    def test_set_analysis_bad_state(self):
        fn = self._make_set_analysis()
        with pytest.raises(ValueError, match="state"):
            fn(
                project_uuid="p",
                component_uuid="c",
                vulnerability_uuid="v",
                state="ACCEPTED",
            )

    def test_set_analysis_bad_justification(self):
        fn = self._make_set_analysis()
        with pytest.raises(ValueError, match="justification"):
            fn(
                project_uuid="p",
                component_uuid="c",
                vulnerability_uuid="v",
                state="NOT_AFFECTED",
                justification="JUST_BECAUSE",
            )

    def test_set_analysis_bad_response(self):
        fn = self._make_set_analysis()
        with pytest.raises(ValueError, match="response"):
            fn(
                project_uuid="p",
                component_uuid="c",
                vulnerability_uuid="v",
                state="NOT_AFFECTED",
                response="PATCH",
            )

    def _make_carry_over(self):
        def carry_over_triage(
            source_project_uuid: str,
            target_project_uuid: str,
            mode: str = "dry_run",
        ) -> dict:
            return {}

        return validated(carry_over_triage)

    def test_carry_over_valid_modes(self):
        fn = self._make_carry_over()
        fn(source_project_uuid="s", target_project_uuid="t", mode="dry_run")
        fn(source_project_uuid="s", target_project_uuid="t", mode="exact")

    def test_carry_over_bad_mode(self):
        fn = self._make_carry_over()
        with pytest.raises(ValueError, match="mode"):
            fn(source_project_uuid="s", target_project_uuid="t", mode="live")
