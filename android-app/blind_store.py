"""Хранилище слепого пира (SQLite) — ТОЛЬКО шифротекст и открытые данные.

Таблицы:
  envelopes(row_id PK, to_pid, env_b64, created_at)
      E2EE-конверты (бинарный формат crypto.py, base64): байты, которые
      слепой пир физически не может прочитать — у него нет ключей.
  announces(peer_id PK, frame, created_at)
      ПОСЛЕДНИЙ подписанный анонс публичных ключей каждого встреченного
      пира (открытые данные; клиенты всё равно проверяют подпись Ed25519).

Гарантия слепоты: модуль не импортирует crypto и не содержит путей
расшифрования — открытый текст сообщений сюда попасть не может.
Файл: <profile>/mailbox.db, права 0600.
"""

from __future__ import annotations

import base64
import sqlite3
import threading
from pathlib import Path

DB_FILENAME = "mailbox.db"


class BlindStore:
    """Потокобезопасная обёртка над mailbox.db слепого пира."""

    def __init__(self, profile_dir: str | Path):
        self.path = Path(profile_dir) / DB_FILENAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self.path.chmod(0o600)
        with self._lock, self._db:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS envelopes (
                    row_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_pid     TEXT NOT NULL,
                    env_b64    TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_env_to ON envelopes(to_pid)"
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS announces (
                    peer_id    TEXT PRIMARY KEY,
                    frame      TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- конверты ---------------------------------------------------------------

    def save_envelope(self, to_pid: str, env: bytes) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO envelopes(to_pid, env_b64, created_at) VALUES (?,?,?)",
                (to_pid, base64.b64encode(env).decode("ascii"), _utc_now()),
            )

    def fetch_envelopes(self, to_pid: str) -> list[tuple[int, bytes]]:
        """Все конверты, адресованные to_pid (без удаления)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT row_id, env_b64 FROM envelopes WHERE to_pid=? ORDER BY row_id",
                (to_pid,),
            ).fetchall()
        return [(r["row_id"], base64.b64decode(r["env_b64"])) for r in rows]

    def delete_envelopes(self, row_ids: list[int]) -> int:
        """Удаляет подтверждённые (ack) конверты. Возвращает число удалённых."""
        if not row_ids:
            return 0
        marks = ",".join("?" * len(row_ids))
        with self._lock, self._db:
            cur = self._db.execute(
                f"DELETE FROM envelopes WHERE row_id IN ({marks})", row_ids
            )
        return cur.rowcount

    def count_envelopes(self) -> int:
        with self._lock:
            return int(
                self._db.execute("SELECT COUNT(*) AS n FROM envelopes").fetchone()["n"]
            )

    # --- анонсы публичных ключей ---------------------------------------------------

    def save_announce(self, announce_frame: dict) -> None:
        """Хранит последний анонс пира (peer_id — первичный ключ)."""
        peer_id = str(announce_frame.get("peer_id", ""))
        if not peer_id:
            return
        import json

        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO announces(peer_id, frame, created_at) "
                "VALUES (?,?,?)",
                (
                    peer_id,
                    json.dumps(announce_frame, ensure_ascii=False),
                    _utc_now(),
                ),
            )

    def all_announces(self) -> list[dict]:
        import json

        with self._lock:
            rows = self._db.execute(
                "SELECT frame FROM announces ORDER BY created_at"
            ).fetchall()
        frames = []
        for r in rows:
            try:
                frames.append(json.loads(r["frame"]))
            except ValueError:
                continue
        return frames


def _utc_now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
