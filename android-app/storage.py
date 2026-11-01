"""Локальное хранение: история сообщений + адресная книга (SQLite).

Схема (v1), таблица messages:
  msg_id     TEXT PRIMARY KEY  — уникальный id сообщения (для дедупликации
                                и квитанций)
  direction  TEXT              — 'in' | 'out'
  peer_id    TEXT              — Peer ID второй стороны
  nick       TEXT              — ник второй стороны на момент сообщения
  text       TEXT              — открытый текст (локально; по сети шёл
                                зашифрованным)
  created_at TEXT              — UTC, ISO-8601
  status     TEXT              — исходящие: sent -> delivered -> read
                                входящие: received

Таблица contacts (Этап 6):
  peer_id    TEXT PRIMARY KEY  — Peer ID контакта
  nick       TEXT              — отображаемое имя
  x25519_pub TEXT              — публичный ключ X25519 (base64); сохраняется
                                ТОЛЬКО из проверенных подписанных анонсов
  updated_at TEXT              — UTC, ISO-8601

БД лежит в каталоге профиля: <profile>/history.db. История и адресная
книга полностью локальны и никуда не синхронизируются (см. ограничения
прототипа).
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

DB_FILENAME = "history.db"

_OUT_RANK = {"sent": 0, "delivered": 1, "read": 2}


class Store:
    """Потокобезопасная обёртка над SQLite-файлом профиля."""

    def __init__(self, profile_dir: str | Path):
        self.path = Path(profile_dir) / DB_FILENAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        # В БД лежит открытый текст переписки — только владелец (0600).
        self.path.chmod(0o600)
        with self._lock, self._db:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id     TEXT UNIQUE NOT NULL,
                    direction  TEXT NOT NULL CHECK(direction IN ('in','out')),
                    peer_id    TEXT NOT NULL,
                    nick       TEXT,
                    text       TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status     TEXT NOT NULL
                )
                """
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_id, id)"
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS contacts (
                    peer_id    TEXT PRIMARY KEY,
                    nick       TEXT NOT NULL,
                    x25519_pub TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # --- запись -----------------------------------------------------------------

    def save_outgoing(self, msg_id: str, peer_id: str, nick: str, text: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO messages"
                "(msg_id, direction, peer_id, nick, text, created_at, status) "
                "VALUES (?,?,?,?,?,?,?)",
                (msg_id, "out", peer_id, nick, text, _utc_now(), "sent"),
            )

    def save_incoming(self, msg_id: str, peer_id: str, nick: str, text: str) -> bool:
        """False, если сообщение с таким msg_id уже записано (дедупликация)."""
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO messages"
                "(msg_id, direction, peer_id, nick, text, created_at, status) "
                "VALUES (?,?,?,?,?,?,?)",
                (msg_id, "in", peer_id, nick, text, _utc_now(), "received"),
            )
        return cur.rowcount > 0

    def mark_status(self, msg_id: str, peer_id: str, status: str) -> bool:
        """Повышает статус исходящего сообщения (sent -> delivered -> read).

        Понижение запрещено: опоздавшая квитанция 'delivered' не откатывает
        уже полученный 'read'. Возвращает True, если статус изменился.
        """
        if status not in _OUT_RANK:
            raise ValueError(f"неизвестный статус: {status}")
        with self._lock:
            row = self._db.execute(
                "SELECT status FROM messages WHERE msg_id=? AND peer_id=? "
                "AND direction='out'",
                (msg_id, peer_id),
            ).fetchone()
            if row is None or _OUT_RANK.get(row["status"], -1) >= _OUT_RANK[status]:
                return False
            with self._db:
                self._db.execute(
                    "UPDATE messages SET status=? WHERE msg_id=?",
                    (status, msg_id),
                )
            return True

    # --- чтение -------------------------------------------------------------------

    def history(self, peer_id: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
        """Последние `limit` сообщений (хронологический порядок)."""
        with self._lock:
            if peer_id:
                rows = self._db.execute(
                    "SELECT * FROM messages WHERE peer_id=? "
                    "ORDER BY id DESC LIMIT ?",
                    (peer_id, limit),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return list(reversed(rows))


    # --- адресная книга (Этап 6) -------------------------------------------------

    def save_contact(self, peer_id: str, nick: str, x25519_pub_b64: str) -> None:
        """Сохраняет/обновляет контакт (ключ — только из проверенного анонса)."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO contacts(peer_id, nick, x25519_pub, updated_at) "
                "VALUES (?,?,?,?)",
                (peer_id, nick, x25519_pub_b64, _utc_now()),
            )

    def get_contact(self, peer_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute(
                "SELECT * FROM contacts WHERE peer_id=?", (peer_id,)
            ).fetchone()

    def list_contacts(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(
                "SELECT * FROM contacts ORDER BY nick"
            ).fetchall()

    def message_status(self, msg_id: str) -> str | None:
        """Текущий статус сообщения по msg_id (для команды send)."""
        with self._lock:
            row = self._db.execute(
                "SELECT status FROM messages WHERE msg_id=?", (msg_id,)
            ).fetchone()
        return row["status"] if row else None


def _utc_now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


class ContactError(Exception):
    """Адресат найден в адресной книге, но неоднозначен."""


def resolve_peer(store: Store, ref: str) -> tuple[str, str] | None:
    """Превращает «ник | Peer ID | уникальный префикс Peer ID» в (peer_id, nick).

    Удобно на телефоне: длинный Peer ID набирать тяжело, ник — легко.
    Возврат None — адресата нет в адресной книге; ContactError — неоднозначность
    (несколько контактов с таким ником/префиксом).
    """
    ref = ref.strip()
    if not ref:
        return None
    rows = store.list_contacts()

    # 1) точное совпадение Peer ID
    for row in rows:
        if row["peer_id"] == ref:
            return row["peer_id"], row["nick"]

    # 2) ник (без учёта регистра)
    by_nick = [row for row in rows if row["nick"].lower() == ref.lower()]
    if len(by_nick) == 1:
        return by_nick[0]["peer_id"], by_nick[0]["nick"]
    if len(by_nick) > 1:
        pids = ", ".join(r["peer_id"][:12] + "…" for r in by_nick)
        raise ContactError(f"ников «{ref}» несколько: {pids} — укажите Peer ID")

    # 3) уникальный префикс Peer ID (не короче 8 символов)
    if len(ref) >= 8:
        by_prefix = [row for row in rows if row["peer_id"].startswith(ref)]
        if len(by_prefix) == 1:
            return by_prefix[0]["peer_id"], by_prefix[0]["nick"]
        if len(by_prefix) > 1:
            raise ContactError(
                f"префикс «{ref}» совпадает с {len(by_prefix)} контактами — уточните"
            )

    return None
