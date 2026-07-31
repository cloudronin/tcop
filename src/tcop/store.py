"""Append-only evidence store and deterministic artifact exports."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes


class EvidenceStore:
    """An immutable SQLite observation log with JSONL export support."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS observations (
              observation_id TEXT PRIMARY KEY,
              observer_id TEXT NOT NULL,
              subject_id TEXT NOT NULL,
              sequence_number INTEGER NOT NULL,
              accepted_at INTEGER NOT NULL,
              payload BLOB NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS protocol_events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL,
              at INTEGER NOT NULL,
              payload TEXT NOT NULL
            )
            """
        )
        self.connection.commit()

    def append_observation(self, observation: Mapping[str, Any], accepted_at: int) -> bool:
        try:
            self.connection.execute(
                "INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?)",
                (
                    observation["observation_id"],
                    observation["observer"]["id"],
                    observation["subject"]["id"],
                    observation["sequence_number"],
                    accepted_at,
                    canonical_bytes(dict(observation)),
                ),
            )
        except sqlite3.IntegrityError:
            return False
        self.connection.commit()
        return True

    def append_protocol_event(self, event_type: str, at: int, payload: Mapping[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO protocol_events(event_type, at, payload) VALUES (?, ?, ?)",
            (event_type, at, json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))),
        )
        self.connection.commit()

    def observations_for(self, subject_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT payload FROM observations WHERE subject_id = ? ORDER BY accepted_at, sequence_number", (subject_id,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def all_observations(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM observations ORDER BY accepted_at, sequence_number").fetchall()
        return [json.loads(row[0]) for row in rows]

    def count_observations(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0])

    def export_evidence_jsonl(self, destination: Path) -> None:
        rows = self.connection.execute("SELECT payload FROM observations ORDER BY accepted_at, sequence_number").fetchall()
        _write_jsonl(destination, (json.loads(row[0]) for row in rows))

    def export_protocol_events_jsonl(self, destination: Path) -> None:
        rows = self.connection.execute("SELECT event_type, at, payload FROM protocol_events ORDER BY event_id").fetchall()
        _write_jsonl(
            destination,
            ({"stream": "protocol", "event_type": row[0], "at": row[1], **json.loads(row[2])} for row in rows),
        )

    def close(self) -> None:
        self.connection.close()


def _write_jsonl(destination: Path, records: Iterable[Mapping[str, Any]]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(dict(record), sort_keys=True, separators=(",", ":")))
            stream.write("\n")


def write_jsonl(destination: Path, records: Iterable[Mapping[str, Any]]) -> None:
    """Public deterministic JSONL writer used by benchmark artifacts."""

    _write_jsonl(destination, records)
