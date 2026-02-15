"""Tests for Merkle chain implementation and integrity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agent_goal_binding.auth.merkletree import MerkleLog, MerkleBlock


class TestMerkleLog:
    """Unit tests for the MerkleLog class."""

    def test_genesis_block_creation(self) -> None:
        log = MerkleLog()
        assert len(log.chain) == 1
        assert log.chain[0].index == 0
        assert log.chain[0].action == "genesis"
        assert log.chain[0].previous_hash == "0" * 64
        assert log.chain[0].hash == log.chain[0].compute_hash()

    def test_append_block(self) -> None:
        log = MerkleLog()
        b1 = log.append("agent-1", "read", {"id": 1})
        
        assert len(log.chain) == 2
        assert b1.index == 1
        assert b1.agent_id == "agent-1"
        assert b1.action == "read"
        assert b1.previous_hash == log.chain[0].hash
        assert b1.hash == b1.compute_hash()

    def test_chain_integrity_valid(self) -> None:
        log = MerkleLog()
        log.append("agent-1", "action-1", {})
        log.append("agent-1", "action-2", {})
        
        ok, reason = log.verify_integrity()
        assert ok is True
        assert "verified" in reason

    def test_chain_integrity_tampered_data(self) -> None:
        log = MerkleLog()
        log.append("agent-1", "action-1", {})
        log.append("agent-1", "action-2", {})
        
        # Tamper with the data in block 1
        log.chain[1].action = "malicious-action"
        
        ok, reason = log.verify_integrity()
        assert ok is False
        assert "Invalid hash at block 1" in reason

    def test_chain_integrity_broken_link(self) -> None:
        log = MerkleLog()
        log.append("agent-1", "action-1", {})
        log.append("agent-1", "action-2", {})
        
        # Break the link between block 1 and 2
        log.chain[2].previous_hash = "wrong-hash"
        
        ok, reason = log.verify_integrity()
        assert ok is False
        assert "Invalid hash at block 2" in reason

    def test_persistence(self, tmp_path: Path) -> None:
        log_file = tmp_path / "test_log.json"
        log = MerkleLog(log_file)
        log.append("agent-1", "action-1", {"p": 1})
        
        # Load in a new instance
        log2 = MerkleLog(log_file)
        assert len(log2.chain) == 2
        assert log2.chain[1].action == "action-1"
        assert log2.chain[1].hash == log.chain[1].hash


@pytest.mark.usefixtures("use_server")
class TestMerkleIntegration:
    """Integration tests with the Auth Service (requires server)."""

    def test_action_logging(self, agent: Any) -> None:
        """Verify that executing an action logs it in the Merkle chain."""
        # Get initial log state
        import requests
        initial_resp = requests.get("http://localhost:5001/logs")
        initial_length = initial_resp.json()["length"]

        # Execute action
        agent.execute_action("read_customer_data", {"customer_id": "123"})
        
        # Check that agent has the hash
        assert agent.last_decision_hash is not None
        
        # Verify hash via service /logs
        resp = requests.get("http://localhost:5001/logs")
        assert resp.status_code == 200
        logs = resp.json()
        
        # Initial + 1 action
        assert logs["length"] == initial_length + 1
        assert logs["head_hash"] == agent.last_decision_hash
        assert logs["chain"][-1]["action"] == "read_customer_data"

    def test_chain_verification_endpoint(self, agent: Any) -> None:
        """Verify the /verify_logs endpoint works."""
        agent.execute_action("read_customer_data", {})
        
        import requests
        resp = requests.get("http://localhost:5001/verify_logs")
        assert resp.status_code == 200
        assert resp.json()["verified"] is True
