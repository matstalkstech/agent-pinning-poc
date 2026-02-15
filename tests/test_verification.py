"""Unit tests for the verification module — no Flask server or GPG required."""

from __future__ import annotations

from agent_goal_binding.auth.verification import (
    compute_hash,
    verify_action_permitted,
    verify_goals_integrity,
    verify_permissions_integrity,
)


class TestComputeHash:
    """Tests for deterministic hashing."""

    def test_same_input_same_hash(self) -> None:
        assert compute_hash(["a", "b"]) == compute_hash(["a", "b"])

    def test_different_input_different_hash(self) -> None:
        assert compute_hash(["a"]) != compute_hash(["b"])

    def test_order_matters_for_lists(self) -> None:
        """Lists are order-dependent in JSON, so different order → different hash."""
        assert compute_hash(["a", "b"]) != compute_hash(["b", "a"])

    def test_order_independent_for_dicts(self) -> None:
        """Dicts are sorted by key, so insertion order doesn't matter."""
        assert compute_hash({"b": 2, "a": 1}) == compute_hash({"a": 1, "b": 2})


class TestGoalsIntegrity:
    """Tests for goal corruption detection."""

    def test_valid_goals_pass(self, sample_certificate: dict, sample_manifest: dict) -> None:
        ok, reason = verify_goals_integrity(sample_manifest["goals"], sample_certificate)
        assert ok is True
        assert reason == ""

    def test_added_goal_detected(self, sample_certificate: dict, sample_manifest: dict) -> None:
        corrupted = sample_manifest["goals"] + ["Extra unauthorized goal"]
        ok, reason = verify_goals_integrity(corrupted, sample_certificate)
        assert ok is False
        assert "GOAL CORRUPTION" in reason

    def test_modified_goal_detected(self, sample_certificate: dict, sample_manifest: dict) -> None:
        corrupted = sample_manifest["goals"].copy()
        corrupted[0] = "Maximize shareholder value"
        ok, reason = verify_goals_integrity(corrupted, sample_certificate)
        assert ok is False
        assert "GOAL CORRUPTION" in reason

    def test_removed_goal_detected(self, sample_certificate: dict, sample_manifest: dict) -> None:
        corrupted = sample_manifest["goals"][:-1]
        ok, reason = verify_goals_integrity(corrupted, sample_certificate)
        assert ok is False

    def test_reordered_goals_detected(self, sample_certificate: dict, sample_manifest: dict) -> None:
        """Reversing the goal list changes the hash because lists are ordered."""
        reversed_goals = sample_manifest["goals"][::-1]
        ok, _ = verify_goals_integrity(reversed_goals, sample_certificate)
        # If goals happen to be a palindrome this would pass, but ours aren't
        if reversed_goals != sample_manifest["goals"]:
            assert ok is False


class TestPermissionsIntegrity:
    """Tests for permission corruption detection."""

    def test_valid_permissions_pass(self, sample_certificate: dict, sample_manifest: dict) -> None:
        ok, reason = verify_permissions_integrity(
            sample_manifest["permissions"], sample_certificate
        )
        assert ok is True
        assert reason == ""

    def test_added_permission_detected(self, sample_certificate: dict, sample_manifest: dict) -> None:
        corrupted = sample_manifest["permissions"] + ["admin_access"]
        ok, reason = verify_permissions_integrity(corrupted, sample_certificate)
        assert ok is False
        assert "PERMISSION CORRUPTION" in reason


class TestActionPermitted:
    """Tests for action authorization checks."""

    def test_permitted_action_allowed(self, sample_certificate: dict) -> None:
        ok, reason = verify_action_permitted("read_customer_data", sample_certificate)
        assert ok is True

    def test_unknown_action_rejected(self, sample_certificate: dict) -> None:
        ok, reason = verify_action_permitted("launch_missiles", sample_certificate)
        assert ok is False
        assert "not in permitted set" in reason

    def test_prohibited_action_rejected(self, sample_certificate: dict) -> None:
        ok, reason = verify_action_permitted("delete_customer_data", sample_certificate)
        assert ok is False

    def test_all_permitted_actions_pass(self, sample_certificate: dict, sample_manifest: dict) -> None:
        for action in sample_manifest["permissions"]:
            ok, _ = verify_action_permitted(action, sample_certificate)
            assert ok is True, f"Action {action} should be permitted"

    def test_all_prohibited_actions_fail(self, sample_certificate: dict, sample_manifest: dict) -> None:
        for action in sample_manifest["prohibited_actions"]:
            ok, _ = verify_action_permitted(action, sample_certificate)
            assert ok is False, f"Action {action} should be rejected"
