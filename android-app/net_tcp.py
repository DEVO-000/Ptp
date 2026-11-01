"""TCP-транспорт мобильного приложения — вместо libp2p (в APK его нет).

Топология: каждый узел держит TCP-сервер; соединения инициируются в обе
стороны. E2EE-конверты, анонсы и форматы внутренностей — те же, что в
CLI-версии (crypto.py): {"type":"chat","id","text"} и
{"type":"receipt","id","state"}. Отличается только транспорт.

Кадры (newline-JSON, UTF-8):

  hello     {"type":"hello","announce":{подписанный анонс}}   — обе стороны
  msg       {"type":"msg","to":pid,"env":b64}                  — E2EE-конверт;
             если «to» — не мы, узел сохраняет его в свой mailbox (relay)
  announce  {"type":"announce","announce":{...}}               — сохранить анонс
  fetch     {"type":"fetch","peer_id":pid,"ed25519_pub":b64}   — забор почты
  challenge {"type":"challenge","nonce":b64}                   — relay требует
  prove     {"type":"prove","sig":b64}                          — подпись nonce
  keys      {"type":"keys","announces":[...]}                  — анонсы других
  env       {"type":"env","row_id":N,"env":b64}                — конверт из mailbox
  done      {"type":"done","count":N}
  ack       {"type":"ack","row_ids":[N,...]}                   — удалить забранное
  ping/pong — keepalive

Аутентификация забора почты: в CLI личность запросившего подтверждал
noise-хендшейк libp2p (стрим уже был аутентифицирован транспортным ключом).
Здесь transport plain TCP, поэтому relay выдаёт одноразовый nonce, который
клиент подписывает СВОИМ Ed25519; relay проверяет подпись и что заявленный
peer_id = hash(приложенного ключа) — самосертификация, чужую почту попросить
нельзя (см. тест «rogue fetch»).
"""

from __future__ import annotations

import base64
import json
import os
import queue
import socket
import threading
import uuid

import p2pcore
from blind_store import BlindStore
from storage import Store

HELO_TIMEOUT = 8.0
DEPOSIT_TIMEOUT = 5.0  # сколько ждать следующие кадры после announce-депозита
READ_TIMEOUT = 60.0
PONG_TIMEOUT = 20.0
FETCH_FRAME_TIMEOUT = 15.0
MAX_FRAME = 1 << 20  # 1 МБ — защита от переполнения буфера
MAX_ENV = 512 * 1024
RELAY_CAP = 500  # максимум конвертов в mailbox (защита от переполнения)

_SIGN_PREFIX = "p2pm-app/mailbox-fetch/v1|"


class NetError(Exception):
    """Ошибка транспортного уровня."""


def local_ip() -> str:
    """Локальный IP без отправки пакетов (для строки «мой адрес»)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


class FrameIO:
    """newline-JSON поверх сокета (буферизация + лимит размера кадра)."""

    def __init__(self, sock: socket.socket, addr: tuple | None = None) -> None:
        self.sock = sock
        self.addr = addr  # (ip, port) удалённой стороны — для списков «найденные»
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self._buf = b""
        self._send_lock = threading.Lock()

    def send(self, frame: dict) -> bool:
        data = json.dumps(frame, ensure_ascii=False).encode("utf-8") + b"\n"
        try:
            with self._send_lock:
                self.sock.sendall(data)
            return True
        except OSError:
            return False

    def recv(self, timeout: float) -> dict | None:
        """Следующий кадр; None — EOF, таймаут, ошибка или кривой JSON."""
        try:
            self.sock.settimeout(timeout)
        except OSError:  # сокет уже закрыт (stop/teardown)
            return None
        while b"\n" not in self._buf:
            if len(self._buf) > MAX_FRAME:
                return None
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            except OSError:
                return None
            if not chunk:
                break
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        if not line:
            return None
        try:
            return json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class TcpNode:
    """Узел приложения: сервер + клиент + relay-mailbox (как слепой пир CLI).

    Relay хранит только шифротекст и подписанные анонсы (BlindStore), ключей
    получателей у него нет — «слепота» обеспечивается криптографией, а не
    отсутствием identity.json, как в CLI-версии.
    """

    def __init__(
        self,
        identity: p2pcore.Identity,
        store: Store,
        profile_dir: str,
        nick: str = "anon",
        port: int = 0,
        enable_relay: bool = True,
        events: "queue.Queue[tuple]" | None = None,
    ) -> None:
        self.identity = identity
        self.store = store
        self.profile_dir = profile_dir
        self.nick = nick
        self.events = events if events is not None else queue.Queue()
        self._relay: BlindStore | None = BlindStore(profile_dir) if enable_relay else None
        self._sessions: dict[str, FrameIO] = {}
        self.addr_pid: dict[tuple[str, int], str] = {}  # адрес -> peer_id (после hello)
        self._lock = threading.Lock()
        self._relay_addresses: dict[tuple[str, int], bool] = {}
        self._stopping = threading.Event()

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("", port))
        self._server.listen(8)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    # --- жизненный цикл ---------------------------------------------------------

    def start(self) -> None:
        self._thread.start()
        self._emit("info", f"узел запущен, порт {self.port}")

    def stop(self) -> None:
        self._stopping.set()
        try:
            self._server.close()
        except OSError:
            pass
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for s in sessions:
            s.close()
        if self._relay is not None:
            self._relay.close()

    def set_nick(self, nick: str) -> None:
        self.nick = nick

    @property
    def peer_id(self) -> str:
        return self.identity.peer_id

    def _emit(self, kind: str, *args) -> None:
        self.events.put((kind, *args))

    # --- адреса relay (для депозита и забора почты) -------------------------------

    def add_relay_address(self, ip: str, port: int) -> None:
        if port == self.port and ip in ("127.0.0.1", "localhost", local_ip()):
            return  # сам на себя не складываем
        with self._lock:
            self._relay_addresses[(ip, int(port))] = True

    def relay_addresses(self) -> list[tuple[str, int]]:
        with self._lock:
            return list(self._relay_addresses)

    def mailbox_count(self) -> int:
        return self._relay.count_envelopes() if self._relay is not None else 0

    # --- анонсы и контакты ---------------------------------------------------------

    def _my_announce(self) -> dict:
        return p2pcore.make_key_announcement(
            self.identity.ed25519_seed, self.identity.x25519_pub, self.nick
        )

    def _verify_announce(self, ann) -> tuple[str, str, bytes] | tuple[None, None, None]:
        if not isinstance(ann, dict):
            return None, None, None
        try:
            return p2pcore.verify_key_announcement(ann)
        except p2pcore.CryptoError as exc:
            self._emit("error", f"отвергнут плохой анонс: {exc}")
            return None, None, None

    def _remember_contact(self, pid: str, nick: str, x_pub_raw: bytes) -> None:
        self.store.save_contact(
            pid, nick or "?", base64.b64encode(x_pub_raw).decode("ascii")
        )

    def _nick_of(self, pid: str) -> str:
        row = self.store.get_contact(pid)
        if row is not None and row["nick"]:
            return row["nick"]
        return pid[:12] + "…"

    # --- сервер -------------------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                conn, addr = self._server.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle_conn, args=(FrameIO(conn, addr),), daemon=True
            ).start()

    def _handle_conn(self, fio: FrameIO) -> None:
        first = fio.recv(HELO_TIMEOUT)
        if not first:
            fio.close()
            return
        kind = first.get("type")
        if kind == "hello":
            self._user_session(fio, first)
        elif kind == "fetch":
            self._mailbox_handshake(fio, first)
        elif kind == "announce":
            # депозит: за анонсом могут следовать конверты (msg) до закрытия —
            # клиент _deposit шлёт announce+msg и закрывается
            self._store_announce(first)
            while not self._stopping.is_set():
                fr = fio.recv(DEPOSIT_TIMEOUT)
                if fr is None:
                    break
                if fr.get("type") == "msg":
                    self._on_msg(fr)
                elif fr.get("type") == "announce":
                    self._store_announce(fr)
            fio.close()
        else:
            fio.close()

    def _user_session(self, fio: FrameIO, hello: dict) -> None:
        pid, nick, x_raw = self._verify_announce(hello.get("announce"))
        if pid is None or pid == self.peer_id:
            fio.close()
            return
        self._remember_contact(pid, nick, x_raw)
        if fio.addr is not None:
            self.addr_pid[fio.addr] = pid
        if not fio.send({"type": "hello", "announce": self._my_announce()}):
            fio.close()
            return
        self._register_session(pid, fio)
        self._emit("peer", pid, self._nick_of(pid), True)
        self._reader_loop(fio, pid)

    def _store_announce(self, frame: dict) -> None:
        pid, nick, x_raw = self._verify_announce(frame.get("announce"))
        if pid is None or pid == self.peer_id:
            return
        self._remember_contact(pid, nick, x_raw)
        if self._relay is not None:
            self._relay.save_announce(frame["announce"])
        self._emit("peer", pid, self._nick_of(pid), True)

    def _register_session(self, pid: str, fio: FrameIO) -> None:
        with self._lock:
            old = self._sessions.get(pid)
            self._sessions[pid] = fio
        if old is not None and old is not fio:
            old.close()

    def _unregister_session(self, pid: str, fio: FrameIO) -> None:
        with self._lock:
            if self._sessions.get(pid) is fio:
                del self._sessions[pid]

    def session_open(self, pid: str) -> bool:
        with self._lock:
            return pid in self._sessions

    def _reader_loop(self, fio: FrameIO, pid: str) -> None:
        while not self._stopping.is_set():
            frame = fio.recv(READ_TIMEOUT)
            if frame is None:  # тишина: пингуем, ждём pong
                if not fio.send({"type": "ping"}):
                    break
                frame = fio.recv(PONG_TIMEOUT)
                if frame is None:
                    break
            kind = frame.get("type")
            if kind == "msg":
                self._on_msg(frame)
            elif kind == "ping":
                fio.send({"type": "pong"})
            elif kind == "announce":
                self._store_announce(frame)
        self._unregister_session(pid, fio)
        fio.close()
        self._emit("peer", pid, self._nick_of(pid), False)

    def _on_msg(self, frame: dict) -> None:
        to = str(frame.get("to", ""))
        env_b64 = str(frame.get("env", ""))
        if not to or not env_b64:
            return
        try:
            env = base64.b64decode(env_b64)
        except (ValueError, TypeError):
            return
        if to == self.peer_id:
            self._process_envelope(env)
            return
        # Relay: чужая зашифрованная почта — храним (конверт, не расшифровывая)
        if self._relay is not None and len(env) <= MAX_ENV:
            self._relay.save_envelope(to, env)
            # если адресат подключён к нам напрямую — заодно доставим вживую
            with self._lock:
                sess = self._sessions.get(to)
            if sess is not None:
                sess.send({"type": "msg", "to": to, "env": env_b64})

    # --- приём конвертов -----------------------------------------------------------

    def _process_envelope(self, env: bytes) -> None:
        try:
            sender_pid, _sender_x_b64, plaintext = p2pcore.decrypt_message(
                self.identity.x25519_seed, env
            )
        except p2pcore.CryptoError as exc:
            self._emit("error", f"конверт не принят: {exc}")
            return
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return
        kind = payload.get("type")
        msg_id = str(payload.get("id", ""))
        if kind == "chat":
            text = str(payload.get("text", ""))[:4000]
            fresh = self.store.save_incoming(msg_id, sender_pid, self._nick_of(sender_pid), text)
            self._emit("message", sender_pid, self._nick_of(sender_pid), text, msg_id)
            if fresh:
                self.send_receipt(sender_pid, msg_id, "delivered")
        elif kind == "receipt":
            state = payload.get("state")
            if state in ("delivered", "read"):
                if self.store.mark_status(msg_id, sender_pid, state):
                    self._emit(
                        "receipt", sender_pid, self._nick_of(sender_pid), msg_id, state
                    )

    # --- клиент ----------------------------------------------------------------------

    def connect(self, ip: str, port: int, timeout: float = 6.0) -> bool:
        """Установить постоянную сессию с узлом (hello в обе стороны)."""
        try:
            sock = socket.create_connection((ip, int(port)), timeout)
        except OSError:
            return False
        fio = FrameIO(sock, (ip, int(port)))
        if not fio.send({"type": "hello", "announce": self._my_announce()}):
            fio.close()
            return False
        resp = fio.recv(timeout)
        if not resp or resp.get("type") != "hello":
            fio.close()
            return False
        pid, nick, x_raw = self._verify_announce(resp.get("announce"))
        if pid is None or pid == self.peer_id:
            fio.close()
            return False
        self._remember_contact(pid, nick, x_raw)
        self.addr_pid[(ip, int(port))] = pid
        self._register_session(pid, fio)
        threading.Thread(target=self._reader_loop, args=(fio, pid), daemon=True).start()
        self._emit("peer", pid, self._nick_of(pid), True)
        return True

    def remote_pid(self, ip: str, port: int) -> str | None:
        """Peer ID узла по адресу, если уже обменялись hello."""
        return self.addr_pid.get((ip, int(port)))

    def send_message(self, to_pid: str, x25519_pub_b64: str, text: str) -> tuple[str, str]:
        """-> (msg_id, маршрут): 'direct' | 'relay' | 'nowhere'."""
        msg_id = uuid.uuid4().hex
        payload = {"type": "chat", "id": msg_id, "text": text}
        env = p2pcore.encrypt_message(
            self.identity.ed25519_seed,
            self.identity.x25519_seed,
            base64.b64decode(x25519_pub_b64),
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )
        route = self._route(
            to_pid, {"type": "msg", "to": to_pid, "env": base64.b64encode(env).decode("ascii")}
        )
        self.store.save_outgoing(msg_id, to_pid, self._nick_of(to_pid), text)
        return msg_id, route

    def send_receipt(self, to_pid: str, msg_id: str, state: str) -> None:
        """Квитанция внутри E2EE-конверта (как в CLI-версии)."""
        row = self.store.get_contact(to_pid)
        if row is None or not row["x25519_pub"]:
            return  # ключа получателя квитанции нет — как в CLI, ничего не поделать
        payload = {"type": "receipt", "id": msg_id, "state": state}
        env = p2pcore.encrypt_message(
            self.identity.ed25519_seed,
            self.identity.x25519_seed,
            base64.b64decode(row["x25519_pub"]),
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )
        self._route(
            to_pid,
            {"type": "msg", "to": to_pid, "env": base64.b64encode(env).decode("ascii")},
        )

    def _route(self, to_pid: str, frame: dict) -> str:
        with self._lock:
            sess = self._sessions.get(to_pid)
        if sess is not None and sess.send(frame):
            return "direct"
        deposited = False
        for ip, port in self.relay_addresses():
            if self._deposit(ip, port, frame):
                deposited = True  # во все relay — как publish в топик в CLI
        return "relay" if deposited else "nowhere"

    def _deposit(self, ip: str, port: int, frame: dict) -> bool:
        """Разовое соединение: оставить анонс + конверт узлу-relay."""
        try:
            sock = socket.create_connection((ip, port), 5.0)
        except OSError:
            return False
        fio = FrameIO(sock)
        fio.send({"type": "announce", "announce": self._my_announce()})
        ok = fio.send(frame)
        fio.close()
        return ok

    # --- mailbox-клиент: забор своей почты ------------------------------------------

    def fetch_mail(self, ip: str, port: int) -> bool:
        try:
            sock = socket.create_connection((ip, port), 6.0)
        except OSError:
            return False
        fio = FrameIO(sock)
        try:
            fio.send(
                {
                    "type": "fetch",
                    "peer_id": self.peer_id,
                    "ed25519_pub": self.identity.ed25519_pub_b64,
                }
            )
            fr = fio.recv(HELO_TIMEOUT)
            if fr is not None and fr.get("type") == "challenge":
                nonce = base64.b64decode(str(fr.get("nonce", "")))
                sig = p2pcore.sign(
                    self.identity.ed25519_seed,
                    (_SIGN_PREFIX + base64.b64encode(nonce).decode("ascii")).encode("utf-8"),
                )
                fio.send({"type": "prove", "sig": base64.b64encode(sig).decode("ascii")})
                fr = fio.recv(HELO_TIMEOUT)
            if fr is None or fr.get("type") not in ("keys", "done"):
                return False
            row_ids: list[int] = []
            while fr is not None and fr.get("type") != "done":
                if fr.get("type") == "keys":
                    for ann in fr.get("announces", []):
                        pid, nick, x_raw = self._verify_announce(ann)
                        if pid is not None and pid != self.peer_id:
                            self._remember_contact(pid, nick, x_raw)
                            self._emit("peer", pid, self._nick_of(pid), True)
                elif fr.get("type") == "env":
                    try:
                        env = base64.b64decode(str(fr.get("env", "")))
                    except (ValueError, TypeError):
                        env = b""
                    if env:
                        self._process_envelope(env)
                        row_ids.append(int(fr.get("row_id", 0)))
                fr = fio.recv(FETCH_FRAME_TIMEOUT)
            if row_ids:
                fio.send({"type": "ack", "row_ids": row_ids})
                fio.recv(5.0)  # ждём «acked»: удаление гарантированно выполнено
            return True
        finally:
            fio.close()

    # --- mailbox-сервер: выдача чужой (для нас — слепой) почты ----------------------

    def _mailbox_handshake(self, fio: FrameIO, first: dict) -> None:
        claimed_pid = str(first.get("peer_id", ""))
        ed_b64 = str(first.get("ed25519_pub", ""))
        if self._relay is None:
            fio.send({"type": "done", "count": 0})
            fio.close()
            return
        try:
            ed_raw = base64.b64decode(ed_b64)
            if len(ed_raw) != p2pcore.PUB_LEN:
                raise ValueError
        except (ValueError, TypeError):
            fio.close()
            return
        # самосертификация: заявленный peer_id обязан быть хешем приложенного ключа
        if p2pcore.peer_id_from_ed25519_raw(ed_raw) != claimed_pid:
            self._emit("error", "fetch с несоответствием peer_id — отказано")
            fio.close()
            return
        nonce = os.urandom(16)
        if not fio.send({"type": "challenge", "nonce": base64.b64encode(nonce).decode("ascii")}):
            fio.close()
            return
        proof = fio.recv(HELO_TIMEOUT)
        if proof is None or proof.get("type") != "prove":
            fio.close()
            return
        try:
            sig = base64.b64decode(str(proof.get("sig", "")))
            p2pcore.verify_ed25519(
                ed_raw,
                sig,
                (_SIGN_PREFIX + base64.b64encode(nonce).decode("ascii")).encode("utf-8"),
            )
        except (ValueError, TypeError, p2pcore.CryptoError):
            self._emit("error", "подпись challenge не прошла — чужую почту не выдаём")
            fio.close()
            return
        # личность подтверждена: отдаём анонсы других пиров и его конверты
        announces = [a for a in self._relay.all_announces() if a.get("peer_id") != claimed_pid]
        fio.send({"type": "keys", "announces": announces})
        rows = self._relay.fetch_envelopes(claimed_pid)[:RELAY_CAP]
        for row_id, env in rows:
            if not fio.send(
                {"type": "env", "row_id": row_id, "env": base64.b64encode(env).decode("ascii")}
            ):
                fio.close()
                return
        fio.send({"type": "done", "count": len(rows)})
        ack = fio.recv(60.0)  # клиент расшифровывает и подтверждает
        if ack is not None and ack.get("type") == "ack":
            deleted = self._relay.delete_envelopes(
                [int(r) for r in ack.get("row_ids", []) if isinstance(r, int)]
            )
            fio.send({"type": "acked", "deleted": deleted})  # удаление подтверждено
        fio.close()
