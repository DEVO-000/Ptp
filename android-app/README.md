# Мобильное приложение (APK) — P2P-мессенджер

Тот же прототип, что и CLI-версия, но с настоящим графическим интерфейсом
(Kivy) и TCP-транспортом вместо libp2p — чтобы собираться в APK через
[buildozer](https://buildozer.readthedocs.io). Результат: **два Android-телефона
в одной Wi-Fi реально переписываются**, без сервера, со сквозным шифрованием.

```
        Wi-Fi (mDNS-обнаружение + TCP)
   ┌──────────┐      E2EE-конверт      ┌──────────┐
   │ телефон A │◄────────────────────►│ телефон B │
   └──────────┘   напрямую или через   └──────────┘
                   relay (третий телефон
                   хранит только шифротекст)
```

## Что общего с CLI-версией, а что отличается

| | CLI (`../messenger.py`, libp2p) | Приложение (здесь, TCP) |
|---|---|---|
| Seed-фраза / identity.json | ✓ | ✓ тот же формат, те же ключи |
| E2EE-конверт v1 (X25519+HKDF+ChaCha20-Poly1305+Ed25519) | ✓ | ✓ побайтово тот же |
| Подписанные анонсы ключей | ✓ | ✓ тот же формат |
| Peer ID = хеш Ed25519-ключа | ✓ | ✓ (выводится без libp2p, кросс-тест) |
| История SQLite (history.db) | ✓ | ✓ та же схема |
| Слепой relay (mailbox, только шифротекст) | ✓ | ✓ (см. ниже) |
| Транспорт | GossipSub + noise | plain TCP + подпись challenge |
| **Совместимость сетей** | — | **CLI-узлы и приложение друг друга не видят** (разный транспорт); конверты, сиды и форматы совместимы |

Почему не libp2p в APK: python-for-android собирает рецепты; для
`cryptography`, `zeroconf`, `sqlite3`, `kivy` рецепты есть, а вот у libp2p
нет цепочки сборки под Android (C-расширения). Поэтому транспорт здесь —
обычные TCP-сокеты, а аутентификация забора почты (в CLI её делал noise)
заменена подписью одноразового nonce ключом Ed25519.

## Как переписываться (после установки APK)

1. Оба телефона подключите к **одной Wi-Fi** (изоляция клиентов в роутере
   мешает mDNS — тогда используйте ручное подключение по IP:PORT).
2. При первом запуске приложение покажет seed-фразу из 24 слов — запишите.
3. Соседи находятся по mDNS автоматически и появляются в «Чатах»
   (контакты и ключи добавляются из подписанных анонсов, подделать нельзя).
4. Либо вручную: «+ Контакт» → адрес вида `192.168.1.5:4242`
   (свой адрес виден в «Настройках»).
5. Пишите; статусы: отправлено → доставлено → прочитано (E2EE-квитанции).
6. Собеседник офлайн? Сообщение уйдёт через **relay** — любой третий
   телефон с приложением (каждый узел хранит для соседей только
   шифротекст, как слепой пир CLI-версии). Когда адресат появится — заберёт.

## Запуск на десктопе (отладка)

```bash
cd android-app
pip install kivy cryptography mnemonic zeroconf
python main.py --profile /tmp/отладочный-профиль
```

Тесты (без дисплея):

```bash
python tests/test_app_net.py      # 38 проверок: TCP, E2EE, relay, rogue-fetch
python tests/test_app_static.py   # KV-разметка, сборка, синхронизация
```

## Сборка APK — три способа

### Способ 1 (рекомендуемый): GitHub Actions — прямо с телефона, без ПК

В репозитории уже есть `.github/workflows/build-apk.yml`: GitHub сам
прогоняет тесты и собирает APK в облаке. Нужен только аккаунт GitHub.

1. Установите Termux (из F-Droid) и Git:
   ```bash
   pkg update
   pkg install -y git
   ```
2. Создайте пустой репозиторий на github.com (из браузера телефона).
3. Загрузите проект (из каталога, где лежит `p2p-messenger`):
   ```bash
   cd p2p-messenger
   git init
   git add .
   git commit -m "P2P messenger"
   git branch -M main
   git remote add origin https://github.com/ВАШ_ЛОГИН/РЕПО.git
   git push -u origin main
   ```
   (логин-пароль спросит git; удобнее Personal Access Token.)
4. Откройте репозиторий на github.com → вкладка **Actions** → job
   `build-apk` → дождитесь зелёной галочки (~15–25 минут).
5. Внутри запуска — раздел **Artifacts** → `p2p-messenger-apk` → скачайте
   APK прямо на телефон.
6. Откройте APK → Android спросит разрешение «из неизвестных источников» —
   разрешите для браузера/проводника. Готово.

Пересборка после правок: `git add . && git commit -m update && git push`.

### Способ 2 (классический): ПК/ноутбук с Linux или WSL

```bash
# нужен Python 3.11+, Java 17 и системные пакеты (Ubuntu/Debian):
sudo apt install -y openjdk-17-jdk automake libtool pkg-config \
    zlib1g-dev libncurses5-dev libffi-dev libssl-dev lld ccache
pip install buildozer cython
cd android-app
buildozer -y android debug     # первый запуск скачает Android SDK/NDK (~2 ГБ)
```

Готовый APK: `android-app/bin/p2pmessenger-*.apk`. Перенесите на телефон
любым способом и откройте.

### Способ 3 (хардкорный): прямо на телефоне в Termux — возможно, но не гарантируется

Официально buildozer поддерживает только desktop Linux/macOS/WSL. На
устройстве его запускают энтузиасты: нужны `openjdk-17`, Android
command-line tools, SDK + NDK (~3–4 ГБ в памяти телефона), и инструменты
NDK приходится чистить `termux-elf-cleaner`-подобными приёмами — сборка
регулярно ломается между версиями. Если хочется попробовать:

```bash
pkg install -y python git openjdk-17
# далее: распаковать cmdline-tools, sdkmanager --licenses,
# установить platform-tools, platforms;android-34, ndk — и очень терпеливо
pip install buildozer cython
cd android-app && buildozer -y android debug
```

Честно: для «собрать APK на телефоне» используйте Способ 1 — он работает
на любом телефоне с браузером и не требует 4 ГБ свободного места.

## Архитектура и протокол (кратко)

- `p2pcore.py` — крипто-ядро без libp2p: BIP39→HKDF→ключи, конверт E2EE v1,
  анонсы, деривация Peer ID (protobuf→identity-multihash→base58;
  совпадение с libp2p проверяется тестом).
- `net_tcp.py` — TCP-узел: постоянные сессии (hello с подписанным анонсом),
  кадры `msg` (E2EE-конверт + адресат), keepalive ping/pong,
  relay-mailbox с challenge-аутентификацией fetch (nonce подписывается
  Ed25519; заявленный peer_id обязан быть хешем ключа — чужую почту
  попросить нельзя, тест «rogue fetch»).
- `discovery.py` — mDNS через zeroconf; на Android берётся
  `WifiManager.MulticastLock` (pyjnius) — без него ядро отбрасывает
  multicast-пакеты.
- `main.py` — Kivy UI: экраны приветствия (seed)/чатов/чата/настроек;
  сетевые потоки отделены от UI очередью событий.
- `storage.py`, `blind_store.py` — те же модули, что в корне
  (синхронизируются `bash sync_core.sh`; history.db совместим с CLI).

## Ограничения мобильной версии

- Только локальная сеть (Wi-Fi без изоляции клиентов); мобильный
  интернет/NAT не поддерживаются — как и в CLI.
- Один узел = один профиль; relay-режим всегда включён (узел хранит для
  соседей до 500 зашифрованных конвертов, FIFO).
- Свайп приложения из «недавних» убивает узел (ограничение Android);
  для долгой работы держите приложение открытым.
- Seed-фраза лежит в profile нешифрованной (ограничение прототипа;
  бэкап в Google отключён в buildozer.spec: `android.allow_backup = 0`).
- APK не подписан release-ключом (debug-сборка) — для Google Play нужна
  своя подпись.
