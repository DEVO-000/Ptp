#!/usr/bin/env python3
"""P2P-мессенджер — мобильное приложение (Kivy).

Тот же E2EE-прототип, что и CLI-версия (те же seed-фразы, те же конверты,
тот же формат history.db), но с графическим интерфейсом и TCP-транспортом
вместо libp2p — чтобы собирался в APK через buildozer (см. README.md).

Запуск на десктопе для отладки:  python main.py [--smoke] [--profile DIR]
  --smoke — построить интерфейс и выйти через 3 секунды (CI-проверка).
"""

from __future__ import annotations

import os
import queue
import sys
import threading

os.environ.setdefault("KIVY_NO_ARGS", "1")
os.environ.setdefault("KIVY_NO_FILELOG", "1")

import kivy

kivy.require("2.3.0")

from kivy.app import App
from kivy.clock import Clock
from kivy.core.text import LabelBase
from kivy.lang import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput

import discovery
import net_tcp
import p2pcore
from storage import Store

# Кириллица: дефолтный Roboto в Kivy её не покрывает — подменяем шрифт.
_HERE = os.path.dirname(os.path.abspath(__file__))
_FONT = os.path.join(_HERE, "fonts", "DejaVuSans.ttf")
_FONT_B = os.path.join(_HERE, "fonts", "DejaVuSans-Bold.ttf")
if os.path.exists(_FONT):
    LabelBase.register("Roboto", fn_regular=_FONT, fn_bold=_FONT_B)

STATUS_RU = {"sent": "отправлено", "delivered": "доставлено", "read": "прочитано"}

KV = """
ScreenManager:
    WelcomeScreen:
        name: 'welcome'
    MainScreen:
        name: 'main'
    ChatScreen:
        name: 'chat'
    SettingsScreen:
        name: 'settings'

<WelcomeScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 16
        spacing: 8
        Label:
            text: 'P2P-мессенджер'
            font_size: '26sp'
            bold: True
            size_hint_y: None
            height: '34sp'
        Label:
            text: 'Ваша seed-фраза (24 слова, BIP39). Запишите её и храните в тайне — это единственный способ восстановить аккаунт.'
            text_size: self.width, None
            height: self.texture_size[1]
            size_hint_y: None
            halign: 'left'
        TextInput:
            id: seed_out
            readonly: True
            multiline: True
            font_size: '13sp'
            size_hint_y: None
            height: '190sp'
        Label:
            text: 'Файл профиля её не шифрует (ограничение прототипа).'
            font_size: '12sp'
            color: 0.95, 0.7, 0.25, 1
            size_hint_y: None
            height: '18sp'
        Button:
            text: 'Я записал фразу — начать'
            size_hint_y: None
            height: '48sp'
            on_release: app.confirm_seed()
        Widget:
            size_hint_y: None
            height: '12sp'
        Label:
            text: 'Или восстановите существующий аккаунт:'
            font_size: '13sp'
            size_hint_y: None
            height: '20sp'
        TextInput:
            id: seed_in
            hint_text: '24 слова через пробел'
            multiline: False
            font_size: '13sp'
            size_hint_y: None
            height: '42sp'
        Button:
            text: 'Восстановить из фразы'
            size_hint_y: None
            height: '48sp'
            on_release: app.restore_seed()

<MainScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 6
        Label:
            text: 'P2P-мессенджер'
            font_size: '20sp'
            bold: True
            size_hint_y: None
            height: '26sp'
        Label:
            id: node_status
            text: 'узел запускается…'
            font_size: '12sp'
            color: 0.55, 0.55, 0.55, 1
            text_size: self.width, None
            height: self.texture_size[1]
            size_hint_y: None
        BoxLayout:
            orientation: 'horizontal'
            spacing: 6
            size_hint_y: None
            height: '44sp'
            Button:
                text: 'Настройки'
                on_release: app.open_settings_screen()
            Button:
                text: '+ Контакт'
                on_release: app.add_contact_popup()
        Label:
            text: 'Чаты (адресная книга)'
            bold: True
            size_hint_y: None
            height: '22sp'
        ScrollView:
            GridLayout:
                id: contacts_list
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: 4
        Label:
            id: found_hdr
            text: 'Найденные в сети: 0'
            bold: True
            size_hint_y: None
            height: '22sp'
        ScrollView:
            GridLayout:
                id: found_list
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: 4

<ChatScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 8
        spacing: 6
        BoxLayout:
            orientation: 'horizontal'
            size_hint_y: None
            height: '46sp'
            spacing: 6
            Button:
                text: '<'
                size_hint_x: None
                width: '46sp'
                font_size: '20sp'
                on_release: app.back_to_main()
            BoxLayout:
                orientation: 'vertical'
                Label:
                    id: chat_title
                    text: 'диалог'
                    font_size: '17sp'
                    bold: True
                    size_hint_y: None
                    height: '24sp'
                Label:
                    id: chat_status
                    text: ''
                    font_size: '11sp'
                    color: 0.55, 0.55, 0.55, 1
                    size_hint_y: None
                    height: '16sp'
        ScrollView:
            GridLayout:
                id: msgs
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: 6
        BoxLayout:
            orientation: 'horizontal'
            size_hint_y: None
            height: '46sp'
            spacing: 6
            TextInput:
                id: msg_in
                multiline: False
                hint_text: 'Сообщение…'
                on_text_validate: app.send_current()
            Button:
                text: '>>'
                size_hint_x: None
                width: '64sp'
                font_size: '18sp'
                on_release: app.send_current()

<SettingsScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 6
        Button:
            text: '< Назад'
            size_hint_y: None
            height: '44sp'
            on_release: app.back_to_main()
        ScrollView:
            GridLayout:
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: 6
                Label:
                    text: 'Мой Peer ID (открытые данные, можно переслать другу)'
                    font_size: '13sp'
                    size_hint_y: None
                    height: '20sp'
                    halign: 'left'
                TextInput:
                    id: pid_out
                    readonly: True
                    font_size: '12sp'
                    size_hint_y: None
                    height: '40sp'
                Label:
                    id: addr_out
                    text: 'мой адрес: …'
                    font_size: '13sp'
                    size_hint_y: None
                    height: '20sp'
                Label:
                    text: 'Мой ник (в анонсах)'
                    font_size: '13sp'
                    size_hint_y: None
                    height: '20sp'
                BoxLayout:
                    orientation: 'horizontal'
                    spacing: 6
                    size_hint_y: None
                    height: '44sp'
                    TextInput:
                        id: nick_in
                        multiline: False
                    Button:
                        text: 'Сохранить'
                        size_hint_x: None
                        width: '110sp'
                        on_release: app.save_nick()
                Button:
                    text: 'Показать seed-фразу'
                    size_hint_y: None
                    height: '44sp'
                    on_release: app.toggle_seed()
                TextInput:
                    id: seed_out
                    readonly: True
                    multiline: True
                    font_size: '12sp'
                    size_hint_y: None
                    height: 0
                Label:
                    id: relay_out
                    text: 'relay (mailbox): …'
                    font_size: '12sp'
                    color: 0.55, 0.55, 0.55, 1
                    size_hint_y: None
                    height: '34sp'
                Label:
                    text: 'Как подключаться: оба телефона в одной Wi-Fi (без изоляции клиентов) — соседи находятся по mDNS. Или вручную: друг вводит ваш адрес вида IP:PORT. Работает в локальной сети; мобильный интернет не поддерживается.'
                    font_size: '12sp'
                    color: 0.55, 0.55, 0.55, 1
                    text_size: self.width, None
                    height: self.texture_size[1]
                    size_hint_y: None
"""


def _short(pid: str, n: int = 10) -> str:
    return pid[:n] + "…" if len(pid) > n else pid


class WelcomeScreen(Screen):
    pass


class MainScreen(Screen):
    pass


class ChatScreen(Screen):
    pass


class SettingsScreen(Screen):
    pass


class P2PMessengerApp(App):
    title = "P2P-мессенджер"

    def build(self):
        self.sm = Builder.load_string(KV)
        self.profile = None
        self.identity = None
        self.store = None
        self.node = None
        self.disc = None
        self.events = queue.Queue()
        self._found: dict[tuple[str, int], str] = {}  # адрес -> pid (mDNS/ручные)
        self._manual: list[list] = []  # [[ip, port], ...] из config.json
        self._current_chat_pid = None
        self._read_sent: set[str] = set()  # кому уже послали квитанцию «прочитано»
        self._maintain_busy = threading.Event()
        self._config = {}
        return self.sm

    # --- запуск / остановка -----------------------------------------------------

    def on_start(self):
        self.profile = self.user_data_dir
        if "--profile" in sys.argv:  # отладка на десктопе
            i = sys.argv.index("--profile")
            if i + 1 < len(sys.argv):
                self.profile = sys.argv[i + 1]
        if p2pcore.identity_exists(self.profile):
            self._open_session()
        else:
            self._pending_identity = p2pcore.generate_identity()
            scr = self.sm.get_screen("welcome")
            scr.ids.seed_out.text = self._pending_identity.mnemonic_str
            self.sm.current = "welcome"
        if "--smoke" in sys.argv:
            Clock.schedule_once(lambda *a: self.stop(), 3.0)

    def on_stop(self):
        if self.node is not None:
            self.node.stop()
        if self.disc is not None:
            self.disc.stop()

    def confirm_seed(self):
        p2pcore.save_identity(self.profile, self._pending_identity)
        self._open_session()

    def restore_seed(self):
        words = self.sm.get_screen("welcome").ids.seed_in.text.strip()
        try:
            self._pending_identity = p2pcore.identity_from_mnemonic(words)
        except p2pcore.IdentityError as exc:
            self._popup("Восстановление", str(exc))
            return
        p2pcore.save_identity(self.profile, self._pending_identity)
        self._open_session()

    def _open_session(self):
        self.identity = p2pcore.load_identity(self.profile)
        self.store = Store(self.profile)
        self._load_config()

        self.node = net_tcp.TcpNode(
            self.identity,
            self.store,
            self.profile,
            nick=self._config.get("nick", "user"),
            port=int(self._config.get("port", 0)),
            events=self.events,
        )
        self.node.start()
        for entry in self._manual:
            self.node.add_relay_address(str(entry[0]), int(entry[1]))
        self._config["port"] = self.node.port
        self._save_config()

        self.disc = discovery.Discovery(
            self.node.port, self.node.peer_id, self.node.nick, on_found=self._peer_found
        )
        self._mdns_ok = True
        try:
            self.disc.start()
        except Exception as exc:  # noqa: BLE001 — mDNS не критичен, есть ручной режим
            self._mdns_ok = False
            self.events.put(("error", f"mDNS недоступен ({exc}) — только ручные адреса"))

        Clock.schedule_interval(self._drain_events, 0.25)
        Clock.schedule_interval(self._maintain, 5.0)
        Clock.schedule_interval(self._fetch_job, 15.0)
        self.sm.current = "main"
        self.refresh_main()

    # --- конфиг ------------------------------------------------------------------

    def _config_path(self):
        import json
        from pathlib import Path

        return Path(self.profile) / "config.json"

    def _load_config(self):
        import json

        path = self._config_path()
        try:
            self._config = json.loads(path.read_text())
        except (OSError, ValueError):
            self._config = {}
        self._manual = [list(m) for m in self._config.get("manual", [])]

    def _save_config(self):
        import json

        self._config["manual"] = self._manual
        self._config["nick"] = self.node.nick
        path = self._config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._config, ensure_ascii=False, indent=2))

    def save_nick(self):
        scr = self.sm.get_screen("settings")
        nick = scr.ids.nick_in.text.strip() or "user"
        self.node.set_nick(nick)
        self._save_config()
        self._popup("Ник", f"Сохранено: {nick}")

    # --- сеть: колбэки и фоновые циклы --------------------------------------------

    def _peer_found(self, ip, port, pid_hint, name):
        """Колбэк из потока zeroconf: только регистрируем адрес."""
        self._found[(ip, port)] = pid_hint
        self.node.add_relay_address(ip, port)

    def _maintain(self, *args):
        if self.node is None or self._maintain_busy.is_set():
            return
        self._maintain_busy.set()
        threading.Thread(target=self._maintain_job, daemon=True).start()

    def _maintain_job(self):
        try:
            for ip, port in self.node.relay_addresses():
                pid = self.node.remote_pid(ip, port)
                if pid is not None and self.node.session_open(pid):
                    continue
                self.node.connect(ip, port)
        finally:
            self._maintain_busy.clear()

    def _fetch_job(self, *args):
        if self.node is None:
            return
        threading.Thread(target=self._fetch_job_body, daemon=True).start()

    def _fetch_job_body(self):
        for ip, port in self.node.relay_addresses():
            self.node.fetch_mail(ip, port)

    # --- события сети -> UI ---------------------------------------------------------

    def _drain_events(self, *args):
        drained = False
        while True:
            try:
                ev = self.events.get_nowait()
            except queue.Empty:
                break
            drained = True
            kind = ev[0]
            if kind == "message":
                _, pid, nick, text, msg_id = ev
                if pid == self._current_chat_pid:
                    self._mark_read(pid, msg_id)
                    self.refresh_chat()
                else:
                    self._set_status(f"новое сообщение от {nick}")
            elif kind == "receipt":
                if ev[1] == self._current_chat_pid:
                    self.refresh_chat()
            elif kind in ("peer", "error", "info"):
                pass  # отражается в статусе/списках при обновлении
        if drained:
            self.refresh_main()

    def _set_status(self, text):
        self.sm.get_screen("main").ids.node_status.text = text

    def _mark_read(self, pid, msg_id):
        if msg_id in self._read_sent:
            return
        self._read_sent.add(msg_id)
        self.node.send_receipt(pid, msg_id, "read")

    # --- экраны ----------------------------------------------------------------------

    def back_to_main(self):
        self._current_chat_pid = None
        self.sm.current = "main"
        self.refresh_main()

    def open_settings_screen(self):
        scr = self.sm.get_screen("settings")
        scr.ids.pid_out.text = self.node.peer_id
        scr.ids.addr_out.text = f"мой адрес: {net_tcp.local_ip()}:{self.node.port}"
        scr.ids.nick_in.text = self.node.nick
        scr.ids.seed_out.height = 0
        scr.ids.seed_out.text = ""
        scr.ids.relay_out.text = (
            f"relay (mailbox): в почте для других {self.node.mailbox_count()} конвертов; "
            "узел хранит для соседей только шифротекст"
        )
        self.sm.current = "settings"

    def toggle_seed(self):
        scr = self.sm.get_screen("settings")
        if scr.ids.seed_out.height == 0:
            scr.ids.seed_out.text = self.identity.mnemonic_str
            scr.ids.seed_out.height = 180
        else:
            scr.ids.seed_out.text = ""
            scr.ids.seed_out.height = 0

    def refresh_main(self):
        if self.node is None or self.sm.current != "main":
            return
        scr = self.sm.get_screen("main")
        contacts = self.store.list_contacts()
        box = scr.ids.contacts_list
        box.clear_widgets()
        for row in contacts:
            has_key = bool(row["x25519_pub"])
            pid = row["peer_id"]
            btn = Button(
                text=(
                    f"{row['nick']}   {_short(pid)}"
                    + ("   [ключ есть]" if has_key else "   [ключа ещё нет]")
                ),
                size_hint_y=None,
                height="44sp",
                halign="left",
            )
            btn.bind(on_release=lambda _b, p=pid: self.open_chat(p))
            box.add_widget(btn)
        if not contacts:
            box.add_widget(
                Label(
                    text="пока никого: найдите соседа в одной Wi-Fi\nили добавьте контакт вручную",
                    font_size="12sp",
                    color=(0.55, 0.55, 0.55, 1),
                    size_hint_y=None,
                    height="40sp",
                )
            )
        # найденные в сети
        found_rows = []
        for (ip, port), pid_hint in self._found.items():
            pid = self.node.remote_pid(ip, port) or pid_hint
            found_rows.append((ip, port, pid))
        scr.ids.found_hdr.text = f"Найденные в сети: {len(found_rows)}"
        fbox = scr.ids.found_list
        fbox.clear_widgets()
        for ip, port, pid in found_rows:
            btn = Button(
                text=f"{ip}:{port}   {_short(pid) if pid else '?'}",
                size_hint_y=None,
                height="40sp",
                halign="left",
            )
            btn.bind(on_release=lambda _b, a=(ip, port): self._try_connect(a))
            fbox.add_widget(btn)
        # статус узла
        mdns = "mDNS ок" if getattr(self, "_mdns_ok", False) else "mDNS нет"
        scr.ids.node_status.text = (
            f"адрес {net_tcp.local_ip()}:{self.node.port} · контактов {len(contacts)} · "
            f"{mdns} · relay {self.node.mailbox_count()} конв."
        )

    def _try_connect(self, addr):
        ip, port = addr
        threading.Thread(
            target=self._connect_job, args=(ip, int(port)), daemon=True
        ).start()

    def _connect_job(self, ip, port):
        ok = self.node.connect(ip, port)
        self.events.put(("info", f"подключение к {ip}:{port}: {'ок' if ok else 'не вышло'}"))
        Clock.schedule_once(lambda *a: self.refresh_main(), 0)

    def open_chat(self, pid):
        self._current_chat_pid = pid
        scr = self.sm.get_screen("chat")
        row = self.store.get_contact(pid)
        nick = row["nick"] if row is not None else _short(pid)
        scr.ids.chat_title.text = f"{nick}  ·  {_short(pid)}"
        self.sm.current = "chat"
        self.refresh_chat()
        # всё показанное входящее помечаем прочитанным (квитанция внутри E2EE)
        for row_msg in self.store.history(peer_id=pid, limit=100):
            if row_msg["direction"] == "in":
                self._mark_read(pid, row_msg["msg_id"])

    def refresh_chat(self):
        pid = self._current_chat_pid
        if pid is None or self.sm.current != "chat":
            return
        scr = self.sm.get_screen("chat")
        scr.ids.chat_status.text = (
            "в сети" if self.node.session_open(pid) else "не в сети (сообщение уйдёт через relay)"
        )
        box = scr.ids.msgs
        box.clear_widgets()
        for row in self.store.history(peer_id=pid, limit=100):
            if row["direction"] == "out":
                text = (
                    f"[b]Вы[/b]  {row['text']}\n"
                    f"[size=11][color=808080]{STATUS_RU.get(row['status'], row['status'])}[/color][/size]"
                )
                color = (0.75, 0.9, 1.0, 1)
            else:
                who = row["nick"] or _short(pid)
                text = f"[b]{who}[/b]  {row['text']}"
                color = (0.85, 1.0, 0.85, 1)
            lbl = Label(
                text=text,
                markup=True,
                size_hint_y=None,
                height=max(34, self._label_height(lbl_text_len=len(row["text"]) + 24)),
                text_size=(self.sm.width - 28, None),
                halign="left",
                valign="middle",
                color=color,
            )
            box.add_widget(lbl)
        if not box.children:
            box.add_widget(
                Label(
                    text="сообщений пока нет",
                    font_size="12sp",
                    color=(0.55, 0.55, 0.55, 1),
                    size_hint_y=None,
                    height="30sp",
                )
            )

    @staticmethod
    def _label_height(lbl_text_len: int) -> int:
        import math

        return 26 * max(1, math.ceil(lbl_text_len / 32))

    def send_current(self):
        scr = self.sm.get_screen("chat")
        text = scr.ids.msg_in.text.strip()
        pid = self._current_chat_pid
        if not text or pid is None:
            return
        row = self.store.get_contact(pid)
        if row is None or not row["x25519_pub"]:
            self._popup(
                "Нет ключа собеседника",
                "Открытый ключ появится, когда собеседник будет в одной сети "
                "(mDNS) или заберёт почту через relay. Тогда сообщение можно "
                "будет зашифровать.",
            )
            return
        scr.ids.msg_in.text = ""
        try:
            _msg_id, route = self.node.send_message(pid, row["x25519_pub"], text)
        except p2pcore.CryptoError as exc:
            self._popup("Ошибка", str(exc))
            return
        note = {
            "direct": "отправлено напрямую",
            "relay": "отправлено через relay (собеседник офлайн)",
            "nowhere": "не отправлено: нет ни прямой связи, ни relay",
        }.get(route, route)
        self.events.put(("info", note))
        self.refresh_chat()

    # --- попапы -------------------------------------------------------------------

    def _popup(self, title: str, text: str):
        content = BoxLayout(orientation="vertical", spacing=6, padding=6)
        content.add_widget(
            Label(
                text=text,
                text_size=(self.sm.width - 60, None),
                size_hint_y=None,
                height=self._label_height(len(text) + 8),
            )
        )
        btn = Button(text="Закрыть", size_hint_y=None, height="44sp")
        content.add_widget(btn)
        popup = Popup(title=title, content=content, size_hint=(0.9, 0.5))
        btn.bind(on_release=popup.dismiss)
        popup.open()

    def add_contact_popup(self):
        box = BoxLayout(orientation="vertical", spacing=6, padding=6)
        pid_in = TextInput(hint_text="Peer ID собеседника (12D3KooW…)", multiline=False)
        nick_in = TextInput(hint_text="Имя (необязательно)", multiline=False)
        addr_in = TextInput(hint_text="IP:порт (необязательно, напр. 192.168.1.5:4242)", multiline=False)
        btn = Button(text="Добавить", size_hint_y=None, height="44sp")
        box.add_widget(pid_in)
        box.add_widget(nick_in)
        box.add_widget(addr_in)
        box.add_widget(btn)
        popup = Popup(title="Добавить контакт", content=box, size_hint=(0.92, 0.55))
        btn.bind(
            on_release=lambda _b: self._add_contact(
                pid_in.text.strip(), nick_in.text.strip(), addr_in.text.strip(), popup
            )
        )
        popup.open()

    def _add_contact(self, pid, nick, addr, popup):
        popup.dismiss()
        if not pid and not addr:
            self._popup("Добавление", "Укажите Peer ID или адрес IP:порт")
            return
        if pid:
            # контакт-заявка: ключ придёт из подписанного анонса (hello/mailbox)
            self.store.save_contact(pid, nick or _short(pid, 12), "")
        if addr and ":" in addr:
            ip, _, port = addr.rpartition(":")
            try:
                entry = [ip.strip(), int(port)]
            except ValueError:
                self._popup("Добавление", f"Неверный адрес: {addr}")
                return
            if entry not in self._manual:
                self._manual.append(entry)
                self._save_config()
            self.node.add_relay_address(entry[0], entry[1])
            self._found[(entry[0], entry[1])] = pid
            self._try_connect((entry[0], entry[1]))
        self.refresh_main()


if __name__ == "__main__":
    P2PMessengerApp().run()
