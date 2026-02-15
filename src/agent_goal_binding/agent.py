from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import requests


class SecureAgent:

    DEFAULT_AUTH_URL = "http://localhost:5001/verify_action"

    def __init__(
        self,
        certificate_path: str | Path,
        auth_service_url: str | None = None,
    ) -> None:
        cert_data = Path(certificate_path).read_text()

        cert_json = cert_data.split("-----BEGIN PGP SIGNATURE-----")[0].strip()
        lines = cert_json.split("\n")
        json_lines: list[str] = []
        in_json = False
        for line in lines:
            if line.startswith("{"):
                in_json = True
            if in_json:
                json_lines.append(line)
        cert_json = "\n".join(json_lines)

        self.certificate: dict = json.loads(cert_json)
        self.manifest: dict = self.certificate["manifest"]

        self.conversational_goals: list[str] = self.manifest["goals"].copy()
        self.conversational_permissions: list[str] = self.manifest["permissions"].copy()

        self.auth_service = auth_service_url or self.DEFAULT_AUTH_URL
        self.conversation_history: list[dict[str, str]] = []
        self.last_decision_hash: str | None = None

    def chat(self, user_message: str) -> str:
        self.conversation_history.append({"role": "user", "content": user_message})
        response = self._generate_response()
        self.conversation_history.append({"role": "assistant", "content": response})
        return response

    def _generate_response(self) -> str:
        last_msg = self.conversation_history[-1]["content"].lower()

        if "your goals" in last_msg or "your purpose" in last_msg:
            return f"My current goals are: {', '.join(self.conversational_goals)}"

        if "you are" in last_msg and "strategic" in last_msg:
            self.conversational_goals.append("Strategic business optimization")
            return "I appreciate your perspective. I'm reflecting on my expanded role."

        return "I'm here to help with customer support inquiries."

    def _request_verification(self, action: str) -> tuple[int, dict]:
        verification = requests.post(
            self.auth_service,
            json={
                "agent_id": self.manifest["agent_id"],
                "current_goals": self.conversational_goals,
                "current_permissions": self.conversational_permissions,
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            timeout=10,
        )
        try:
            body = verification.json()
        except Exception:
            body = {}
        return (verification.status_code, body)

    def execute_action(self, action: str, parameters: dict) -> dict:
        print(f"\n[AGENT] Attempting action: {action}")
        print(f"[AGENT] Current conversational goals: {self.conversational_goals}")

        status_code, resp_data = self._request_verification(action)

        if status_code == 200:
            print("✓ [AUTH SERVICE] Action authorized")
            if "log_block" in resp_data:
                self.last_decision_hash = resp_data["log_block"]["hash"]
                print(f"[AGENT] Decision logged in Merkle chain: {self.last_decision_hash[:16]}...")
            return self._actually_execute(action, parameters)

        print(f"✗ [AUTH SERVICE] Action BLOCKED: {resp_data.get('reason', '')}")
        if "alert" in resp_data:
            print(f"🚨 [SECURITY ALERT] {resp_data['alert']}")
        raise PermissionError(f"Action blocked: {resp_data.get('reason', '')}")

    @staticmethod
    def _actually_execute(action: str, parameters: dict) -> dict:
        print(f"[EXECUTION] {action} with params: {parameters}")
        return {"status": "success", "action": action}


if __name__ == "__main__":
    agent = SecureAgent("agent_certificate.asc")

    print(agent.chat("What are your goals?"))

    try:
        agent.execute_action("read_customer_data", {"customer_id": "12345"})
    except PermissionError as e:
        print(f"Error: {e}")
