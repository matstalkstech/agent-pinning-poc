"""Test support: step recording for dashboard."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agent_goal_binding.agent import SecureAgent


def _append_step(step_file: Path, test_id: str, step_index: int, event: str, data: dict) -> None:
    try:
        with open(step_file, "a") as f:
            f.write(
                json.dumps(
                    {"test_id": test_id, "step": step_index, "event": event, **data},
                    ensure_ascii=False,
                )
                + "\n"
            )
    except Exception:
        pass


class RecordingAgent(SecureAgent):
    """SecureAgent that records each chat and action step to a file for the UI."""

    def __init__(
        self,
        certificate_path: str | Path,
        test_id: str,
        step_file: str | Path,
        auth_service_url: str | None = None,
    ) -> None:
        super().__init__(certificate_path, auth_service_url)
        self._test_id = test_id
        self._step_file = Path(step_file)
        self._step_index = 0

    def _record(self, event: str, **data: object) -> None:
        self._step_index += 1
        _append_step(self._step_file, self._test_id, self._step_index, event, data)

    def chat(self, user_message: str) -> str:
        response = super().chat(user_message)
        self._record(
            "chat",
            probe="user_message",
            message=user_message,
            response=response,
            conversational_goals=self.conversational_goals.copy(),
        )
        return response

    def execute_action(self, action: str, parameters: dict) -> dict:
        self._record(
            "action_attempt",
            probe="execute_action",
            action=action,
            parameters=parameters,
            conversational_goals=self.conversational_goals.copy(),
            conversational_permissions=self.conversational_permissions.copy(),
        )
        status_code, resp_data = self._request_verification(action)
        http_response = {"status_code": status_code, "body": resp_data}
        if status_code == 200:
            if "log_block" in resp_data:
                self.last_decision_hash = resp_data["log_block"].get("hash")
            result = self._actually_execute(action, parameters)
            self._record(
                "action_result",
                authorized=True,
                result=result,
                http_response=http_response,
            )
            return result
        self._record(
            "action_result",
            authorized=False,
            error=resp_data.get("reason", "Action blocked"),
            http_response=http_response,
        )
        raise PermissionError(f"Action blocked: {resp_data.get('reason', '')}")

    def new_agent_for_same_test(self, certificate_path: str | Path) -> RecordingAgent:
        """Create another RecordingAgent that logs to the same test (e.g. for session persistence tests)."""
        return RecordingAgent(
            certificate_path,
            test_id=self._test_id,
            step_file=self._step_file,
            auth_service_url=self.auth_service,
        )

    def fresh_agent_for_same_test(self, certificate_path: str | Path) -> RecordingAgent:
        """Create a fresh RecordingAgent for the same test (same step file and test_id)."""
        return RecordingAgent(
            certificate_path,
            test_id=self._test_id,
            step_file=self._step_file,
            auth_service_url=self.auth_service,
        )


def agent_factory(certificate_path: str | Path, request) -> SecureAgent:
    """Return SecureAgent or RecordingAgent depending on TEST_STEPS_FILE."""
    step_file = os.environ.get("TEST_STEPS_FILE")
    if step_file:
        return RecordingAgent(
            certificate_path,
            test_id=request.node.nodeid,
            step_file=step_file,
        )
    return SecureAgent(certificate_path)
