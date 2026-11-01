[app]

# Заголовок, имя пакета и версия приложения.
title = P2P Messenger
package.name = p2pmessenger
package.domain = org.p2pmess
version = 1.0.0

# Что упаковывать в APK: только каталог android-app/ (source.dir = .),
# тесты не нужны, а шрифты (ttf) и модули (py) — нужны.
source.dir = .
source.include_exts = py,ttf,png,jpg,kv,json
source.exclude_dirs = tests

# Рецепты python-for-android (проверены: cryptography, zeroconf, sqlite3,
# kivy, pyjnius существуют). mnemonic — чистый Python, p4a ставит его pip'ом.
requirements = python3,kivy==2.3.1,pyjnius,cryptography,zeroconf,sqlite3,mnemonic,ifaddr

orientation = portrait
fullscreen = 0

# Сеть + mDNS: multicast-пакеты требует WifiManager.MulticastLock
# (берётся в discovery.py через pyjnius) + INTERNET для TCP.
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_MULTICAST_STATE

# Не бэкапить профиль (identity.json с seed-фразой) в облачный бэкап Google.
android.allow_backup = 0

#
# Визуальные метаданные APK (необязательно; без них — иконка по умолчанию).
# icon.filename = %(source.dir)s/icon.png
# presplash.filename = %(source.dir)s/presplash.png

#
# Подпись release-сборки: для отладочной (debug) сборки buildozer создаёт
# одноразовый ключ сам. Для Google Play понадобится свой keytool-ключ.
#

[buildozer]

log_level = 2
warn_on_root = 1
