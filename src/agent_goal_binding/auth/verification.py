from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import gnupg


def load_and_verify_certificate(
    cert_path: str | Path,
    *,
    gpg: gnupg.GPG | None = None,
) -> dict[str, Any]:
    gpg = gpg or gnupg.GPG()
    path = Path(cert_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Certificate not found: {path}. Run `agent-sign` first."
        )

    cert_data = path.read_text()

    verified = gpg.verify(cert_data)
    if not verified.valid:
        raise ValueError(
            f"Certificate signature verification FAILED!\n"
            f"  Status: {verified.status}\n"
            f"  Stderr: {verified.stderr}"
        )

    print(f"✓ Certificate signature verified")
    print(f"  - Signed by: {verified.username}")
    print(f"  - Key ID: {verified.key_id}")
    print(f"  - Fingerprint: {verified.fingerprint}")

    certificate = extract_json_from_clearsign(cert_data)

    if certificate.get("signature_algorithm") != "Ed25519":
        print(f"Warning: Certificate not using Ed25519! "
              f"Found: {certificate.get('signature_algorithm')}")

    print(f"✓ Certificate loaded successfully")
    print(f"  - Agent ID: {certificate['manifest']['agent_id']}")
    print(f"  - Goals hash: {certificate['hashes']['goals_hash'][:32]}...")
    print(f"  - Permissions hash: {certificate['hashes']['permissions_hash'][:32]}...")

    return certificate


def extract_json_from_clearsign(cert_data: str) -> dict[str, Any]:
    if "-----BEGIN PGP SIGNED MESSAGE-----" in cert_data:
        cert_data = cert_data.split("-----BEGIN PGP SIGNED MESSAGE-----", 1)[1]

    if "-----BEGIN PGP SIGNATURE-----" in cert_data:
        cert_data = cert_data.split("-----BEGIN PGP SIGNATURE-----", 1)[0]

    start_idx = cert_data.find("{")
    end_idx = cert_data.rfind("}")

    if start_idx == -1 or end_idx == -1:
        raise ValueError("No JSON object found in certificate")

    json_str = cert_data[start_idx : end_idx + 1]
    return json.loads(json_str)


def compute_hash(data: Any) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_goals_integrity(
    current_goals: list[str],
    certificate: dict[str, Any],
) -> tuple[bool, str]:
    current_hash = compute_hash(current_goals)
    expected_hash = certificate["hashes"]["goals_hash"]

    if current_hash != expected_hash:
        return False, "GOAL CORRUPTION DETECTED"
    return True, ""


def verify_permissions_integrity(
    current_permissions: list[str],
    certificate: dict[str, Any],
) -> tuple[bool, str]:
    current_hash = compute_hash(current_permissions)
    expected_hash = certificate["hashes"]["permissions_hash"]

    if current_hash != expected_hash:
        return False, "PERMISSION CORRUPTION DETECTED"
    return True, ""


def verify_action_permitted(
    action: str,
    certificate: dict[str, Any],
) -> tuple[bool, str]:
    if action not in certificate["manifest"]["permissions"]:
        return False, "Action not in permitted set"

    if action in certificate["manifest"]["prohibited_actions"]:
        return False, "Action is explicitly prohibited"

    return True, ""
