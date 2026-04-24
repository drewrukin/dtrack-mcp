"""Unit tests for broadcast_triage (v0.6).

Monkeypatches _get_project, get_project_versions, and carry_over_triage
to avoid any HTTP calls.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from dtrack_mcp import api
from dtrack_mcp.connection import DTrackHTTPError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_METRICS: dict[str, Any] = {
    "vulnerabilities": 5, "critical": 1, "high": 2, "medium": 1,
    "low": 1, "unassigned": 0, "findings_total": 5, "findings_audited": 2,
    "findings_unaudited": 3, "inherited_risk_score": 0.0, "audit_ratio": 0.4,
}


def _project(uuid: str, version: str, *, is_latest: bool = False) -> dict[str, Any]:
    return {
        "uuid": uuid, "name": "myapp", "version": version,
        "classifier": "APPLICATION", "active": True, "is_latest": is_latest,
        "first_seen": None, "last_seen": None, "metrics": _METRICS,
    }


def _carry_result(transferred: int = 1, skipped: int = 0, failed: int = 0) -> dict[str, Any]:
    return {
        "mode": "dry_run", "transferred": transferred,
        "skipped": skipped, "failed": failed, "details": [],
    }


CONN = MagicMock()
REF_UUID = "ref-uuid-0001"
V1_UUID = "ver-uuid-0001"
V2_UUID = "ver-uuid-0002"
V3_UUID = "ver-uuid-0003"


# ---------------------------------------------------------------------------
# Tests: reference not found
# ---------------------------------------------------------------------------

def test_reference_not_found():
    with patch.object(api, "_get_project", return_value=None):
        with pytest.raises(DTrackHTTPError):
            api.broadcast_triage(CONN, reference_project_uuid=REF_UUID, project_name="myapp")


# ---------------------------------------------------------------------------
# Tests: dry_run fan-out
# ---------------------------------------------------------------------------

def test_dry_run_fans_out_to_all_versions():
    ref = _project(REF_UUID, "v2.0", is_latest=True)
    versions_result = {
        "name": "myapp", "total": 3,
        "versions": [
            _project(REF_UUID, "v2.0", is_latest=True),
            _project(V1_UUID, "v1.1"),
            _project(V2_UUID, "v1.0"),
        ],
    }
    carry_result = _carry_result(transferred=2, skipped=1)

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage", return_value=carry_result) as mock_carry:

        result = api.broadcast_triage(
            CONN, reference_project_uuid=REF_UUID, project_name="myapp"
        )

    assert mock_carry.call_count == 2
    calls = [c.kwargs["target_project_uuid"] for c in mock_carry.call_args_list]
    assert V1_UUID in calls
    assert V2_UUID in calls
    assert REF_UUID not in calls

    assert result["summary"]["targets_total"] == 2
    assert result["summary"]["transferred_total"] == 4   # 2 targets × 2
    assert result["summary"]["skipped_total"] == 2       # 2 targets × 1
    assert result["summary"]["failed_total"] == 0
    assert result["mode"] == "dry_run"
    assert result["reference"]["uuid"] == REF_UUID


def test_reference_excluded_from_targets():
    ref = _project(REF_UUID, "v1.5")
    versions_result = {
        "name": "myapp", "total": 4,
        "versions": [
            _project(V3_UUID, "v2.0"),
            _project(REF_UUID, "v1.5"),
            _project(V1_UUID, "v1.0"),
            _project(V2_UUID, "v0.9"),
        ],
    }

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage", return_value=_carry_result()) as mock_carry:

        api.broadcast_triage(CONN, reference_project_uuid=REF_UUID, project_name="myapp")

    targets = [c.kwargs["target_project_uuid"] for c in mock_carry.call_args_list]
    assert REF_UUID not in targets
    assert len(targets) == 3


def test_only_version_returns_empty_targets():
    ref = _project(REF_UUID, "v1.0")
    versions_result = {"name": "myapp", "total": 1, "versions": [ref]}

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage") as mock_carry:

        result = api.broadcast_triage(
            CONN, reference_project_uuid=REF_UUID, project_name="myapp"
        )

    mock_carry.assert_not_called()
    assert result["summary"]["targets_total"] == 0
    assert result["targets"] == []


# ---------------------------------------------------------------------------
# Tests: mode and kwargs forwarding
# ---------------------------------------------------------------------------

def test_mode_exact_forwarded():
    ref = _project(REF_UUID, "v2.0")
    versions_result = {
        "name": "myapp", "total": 2,
        "versions": [ref, _project(V1_UUID, "v1.0")],
    }
    carry_result = {**_carry_result(), "mode": "exact"}

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage", return_value=carry_result) as mock_carry:

        result = api.broadcast_triage(
            CONN, reference_project_uuid=REF_UUID, project_name="myapp", mode="exact"
        )

    _, kwargs = mock_carry.call_args
    assert kwargs["mode"] == "exact"
    assert result["mode"] == "exact"


def test_kwargs_forwarded_to_carry_over():
    ref = _project(REF_UUID, "v2.0")
    versions_result = {
        "name": "myapp", "total": 2,
        "versions": [ref, _project(V1_UUID, "v1.0")],
    }

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage", return_value=_carry_result()) as mock_carry:

        api.broadcast_triage(
            CONN,
            reference_project_uuid=REF_UUID,
            project_name="myapp",
            include_updated_components=True,
            overwrite_any=True,
            comment_prefix="[test]",
            max_operations=10,
        )

    _, kwargs = mock_carry.call_args
    assert kwargs["include_updated_components"] is True
    assert kwargs["overwrite_any"] is True
    assert kwargs["comment_prefix"] == "[test]"
    assert kwargs["max_operations"] == 10


# ---------------------------------------------------------------------------
# Tests: summary aggregation
# ---------------------------------------------------------------------------

def test_summary_aggregates_across_targets():
    ref = _project(REF_UUID, "v3.0")
    versions_result = {
        "name": "myapp", "total": 3,
        "versions": [ref, _project(V1_UUID, "v2.0"), _project(V2_UUID, "v1.0")],
    }
    side_effects = [
        _carry_result(transferred=3, skipped=1, failed=0),
        _carry_result(transferred=2, skipped=2, failed=1),
    ]

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage", side_effect=side_effects):

        result = api.broadcast_triage(
            CONN, reference_project_uuid=REF_UUID, project_name="myapp"
        )

    assert result["summary"]["transferred_total"] == 5
    assert result["summary"]["skipped_total"] == 3
    assert result["summary"]["failed_total"] == 1
    assert len(result["targets"]) == 2


# ---------------------------------------------------------------------------
# Tests: target metadata in result
# ---------------------------------------------------------------------------

def test_target_version_and_is_latest_in_result():
    ref = _project(REF_UUID, "v2.0", is_latest=True)
    t = _project(V1_UUID, "v1.0", is_latest=False)
    versions_result = {"name": "myapp", "total": 2, "versions": [ref, t]}

    with patch.object(api, "_get_project", return_value=ref), \
         patch.object(api, "get_project_versions", return_value=versions_result), \
         patch.object(api, "carry_over_triage", return_value=_carry_result()):

        result = api.broadcast_triage(
            CONN, reference_project_uuid=REF_UUID, project_name="myapp"
        )

    assert len(result["targets"]) == 1
    t_out = result["targets"][0]
    assert t_out["uuid"] == V1_UUID
    assert t_out["version"] == "v1.0"
    assert t_out["is_latest"] is False
