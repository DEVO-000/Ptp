"""mDNS-обнаружение соседей по Wi-Fi (zeroconf, без libp2p).

Сервис _p2pmess._tcp.local. В TXT лежат только открытые данные: peer_id и
ник. Полный подписанный анонс ключей обменяется при подключении (hello) и
проверится подписью Ed25519 — TXT-записи вообще ничему не доверяем.

На Android приём multicast-пакетов ядро блокирует, пока приложение не держит
WifiManager.MulticastLock — берём его через pyjnius (в APK). На десктопе
pyjnius нет — просто пропускаем.
"""

from __future__ import annotations

import socket

SERVICE_TYPE = "_p2pmess._tcp.local."


def acquire_multicast_lock():
    """Android: удерживать MulticastLock всё время жизни приложения."""
    try:
        from jnius import autoclass  # только внутри APK (pyjnius)

        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        Context = autoclass("android.content.Context")
        WifiManager = autoclass("android.net.wifi.WifiManager")
        wm = PythonActivity.mActivity.getSystemService(Context.WIFI_SERVICE)
        lock = wm.createMulticastLock("p2p-messenger-mdns")
        lock.setReferenceCounted(False)
        lock.acquire()
        return lock
    except Exception:  # noqa: BLE001 — десктоп, или нет Wi-Fi: не критично
        return None


def _local_ip() -> str:
    from net_tcp import local_ip

    return local_ip()


def _safe_name(nick: str, peer_id: str) -> str:
    keep = "".join(c if c.isalnum() else "-" for c in nick)[:16].strip("-")
    return (keep or "peer") + "-" + peer_id.replace(" ", "")[:12]


class Discovery:
    """Регистрирует себя и слушит соседей; on_found(ip, port, pid_hint, name)."""

    def __init__(self, port: int, peer_id: str, nick: str, on_found) -> None:
        self.port = port
        self.peer_id = peer_id
        self.nick = nick
        self.on_found = on_found
        self._zc = None
        self._info = None
        self._lock = None  # MulticastLock (Android)

    def start(self) -> None:
        from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

        self._lock = acquire_multicast_lock()
        self._zc = Zeroconf()
        name = f"{_safe_name(self.nick, self.peer_id)}.{SERVICE_TYPE}"
        self._info = ServiceInfo(
            SERVICE_TYPE,
            name,
            port=self.port,
            properties={"pid": self.peer_id, "nick": self.nick},
            addresses=[socket.inet_aton(_local_ip())],
        )
        self._zc.register_service(self._info)
        ServiceBrowser(self._zc, SERVICE_TYPE, listener=self)

    # --- колбэки ServiceBrowser (вызываются из потока zeroconf) ---

    def add_service(self, zc, type_: str, name: str) -> None:
        if self._info is not None and name == self._info.name:
            return  # сами себя не «находим»
        try:
            info = zc.get_service_info(type_, name, timeout=2500)
        except Exception:  # noqa: BLE001
            return
        if info is None or not info.addresses or not info.port:
            return
        props = info.properties or {}
        # ключи TXT-записей приходят байтами (zeroconf >= 0.13x)
        raw_pid = props.get("pid") or props.get(b"pid") or b""
        pid_hint = raw_pid.decode("utf-8", "replace") if isinstance(raw_pid, bytes) else str(raw_pid)
        try:
            ip = socket.inet_ntoa(info.addresses[0])
        except OSError:
            return
        self.on_found(ip, int(info.port), str(pid_hint), name)

    def update_service(self, zc, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc, type_: str, name: str) -> None:
        pass

    def stop(self) -> None:
        try:
            if self._zc is not None:
                if self._info is not None:
                    self._zc.unregister_service(self._info)
                self._zc.close()
        except Exception:  # noqa: BLE001
            pass
        finally:
            if self._lock is not None:
                try:
                    self._lock.release()
                except Exception:  # noqa: BLE001
                    pass
                self._lock = None
