from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import gnupg


def sign_agent_manifest(
    manifest_path: str | Path,
    key_id: str,
    output_path: str | Path = "config/agent_certificate.asc",
) -> dict:
    gpg = gnupg.GPG(options=["--pinentry-mode", "loopback"])

    keys = gpg.list_keys(True, keys=[key_id])
    if not keys:
        print(f"Error: Key {key_id} not found")
        sys.exit(1)

    key_info = keys[0]
    key_curve = key_info.get("curve", "")
    if "ed25519" not in key_curve.lower():
        print(f"Warning: Key may not be Ed25519. Curve: {key_curve or 'unknown'}")
        print("For best security, use Ed25519 keys.")

    manifest = json.loads(Path(manifest_path).read_text())

    goals_hash = _deterministic_hash(manifest["goals"])
    perms_hash = _deterministic_hash(manifest["permissions"])
    manifest_hash = _deterministic_hash(manifest)

    certificate = {
        "version": "1.0",
        "signature_algorithm": "Ed25519",
        "key_id": key_id,
        "manifest": manifest,
        "hashes": {
            "goals_hash": goals_hash,
            "permissions_hash": perms_hash,
            "manifest_hash": manifest_hash,
        },
    }

    cert_json = json.dumps(certificate, indent=2, sort_keys=True)

    print(f"Signing manifest with key: {key_id}")
    signed_data = gpg.sign(
        "\n" + cert_json,
        keyid=key_id,
        detach=False,
        clearsign=True,
        passphrase="",
    )

    signed_text = str(signed_data)

    if "-----BEGIN PGP SIGNATURE-----" not in signed_text:
        print("Error: Signing failed — no signature block produced!")
        print(f"GPG stderr: {signed_data.stderr}")
        print()
        print("Hint: If GPG cannot access pinentry, try:")
        print('  export GPG_TTY=$(tty)')
        print("  — or add 'allow-loopback-pinentry' to ~/.gnupg/gpg-agent.conf")
        sys.exit(1)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(signed_text)

    print(f"\n✓ Certificate created and signed successfully")
    print(f"✓ Signature algorithm: Ed25519")
    print(f"✓ Output file: {out}")
    print(f"\n  Cryptographic Hashes:")
    print(f"  - Goals:       {goals_hash[:32]}...")
    print(f"  - Permissions: {perms_hash[:32]}...")
    print(f"  - Manifest:    {manifest_hash[:32]}...")

    print(f"\n  Verifying signature...")
    verified = gpg.verify(signed_text)
    if verified.valid:
        print(f"✓ Signature valid!")
        print(f"  - Signed by: {verified.username}")
        print(f"  - Key ID: {verified.key_id}")
    else:
        print(f"✗ Signature verification failed: {verified.status}")

    return certificate


def _deterministic_hash(data: object) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign an agent manifest with a GPG key",
    )
    parser.add_argument(
        "manifest",
        help="Path to the agent manifest JSON file",
    )
    parser.add_argument(
        "key_id",
        help="GPG key ID or fingerprint to sign with",
    )
    parser.add_argument(
        "-o", "--output",
        default="config/agent_certificate.asc",
        help="Output path for the signed certificate (default: config/agent_certificate.asc)",
    )
    args = parser.parse_args()

    sign_agent_manifest(args.manifest, args.key_id, args.output)


if __name__ == "__main__":
    main()
