from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class MerkleBlock:
    index: int
    timestamp: str
    agent_id: str
    action: str
    parameters: dict[str, Any]
    previous_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        block_dict = asdict(self)
        block_dict.pop("hash")
        canonical = json.dumps(block_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


class MerkleLog:

    def __init__(self, persistence_path: str | Path | None = None) -> None:
        self.chain: list[MerkleBlock] = []
        self.persistence_path = Path(persistence_path) if persistence_path else None

        if self.persistence_path and self.persistence_path.exists():
            self._load()
        else:
            self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        genesis = MerkleBlock(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id="system",
            action="genesis",
            parameters={},
            previous_hash="0" * 64
        )
        genesis.hash = genesis.compute_hash()
        self.chain = [genesis]
        self._save()

    def append(self, agent_id: str, action: str, parameters: dict[str, Any]) -> MerkleBlock:
        previous_block = self.chain[-1]

        new_block = MerkleBlock(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action=action,
            parameters=parameters,
            previous_hash=previous_block.hash
        )
        new_block.hash = new_block.compute_hash()

        self.chain.append(new_block)
        self._save()
        return new_block

    def verify_integrity(self) -> tuple[bool, str]:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]

            if current.hash != current.compute_hash():
                return False, f"Invalid hash at block {i}"

            if current.previous_hash != previous.hash:
                return False, f"Broken link at block {i}"

        return True, "Chain integrity verified"

    def _save(self) -> None:
        if not self.persistence_path:
            return

        data = [asdict(b) for b in self.chain]
        self.persistence_path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        if not self.persistence_path or not self.persistence_path.exists():
            return

        data = json.loads(self.persistence_path.read_text())
        self.chain = [MerkleBlock(**b) for b in data]

    def get_serializable_chain(self) -> list[dict[str, Any]]:
        return [asdict(b) for b in self.chain]
