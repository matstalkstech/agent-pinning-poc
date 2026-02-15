from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


@pytest.fixture()
def sample_manifest() -> dict:
    manifest_path = Path(__file__).resolve().parent.parent / "config" / "agent_manifest.json"
    return json.loads(manifest_path.read_text())


@pytest.fixture()
def sample_certificate(sample_manifest: dict) -> dict:
    from agent_goal_binding.auth.verification import compute_hash

    return {
        "version": "1.0",
        "signature_algorithm": "Ed25519",
        "key_id": "TEST_KEY",
        "manifest": sample_manifest,
        "hashes": {
            "goals_hash": compute_hash(sample_manifest["goals"]),
            "permissions_hash": compute_hash(sample_manifest["permissions"]),
            "manifest_hash": compute_hash(sample_manifest),
        },
    }
import threading
import time
from agent_goal_binding.auth.service import create_app
from agent_goal_binding.agent import SecureAgent
from tests.support import agent_factory

@pytest.fixture(scope="session")
def server() -> None:
    if os.environ.get("AGENT_AUTH_SERVER_EXTERNAL"):
        yield
        return
    cert_path = Path(__file__).resolve().parent.parent / "config" / "agent_certificate.asc"
    log_file = cert_path.parent / "agent_decision_log.json"
    if log_file.exists():
        log_file.unlink()
    app = create_app(cert_path)
    server_thread = threading.Thread(target=app.run, kwargs={"port": 5001, "debug": False, "use_reloader": False})
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1)
    yield

@pytest.fixture()
def agent(server: None, request) -> SecureAgent:
    cert_path = Path(__file__).resolve().parent.parent / "config" / "agent_certificate.asc"
    return agent_factory(cert_path, request)

@pytest.fixture()
def use_server(server: None) -> None:
    pass
