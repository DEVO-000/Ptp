#!/bin/bash
# ============================================================================
# sync_core.sh — синхронизация общих модулей из корня проекта в android-app/.
#
# В APK (buildozer) попадает только каталог android-app/, а storage.py и
# blind_store.py не зависят от libp2p и потому используются обеими версиями
# (CLI и приложение). Запускайте после правок в корне:
#
#   bash android-app/sync_core.sh
# ============================================================================
set -e
cd "$(dirname "$0")/.."

cp storage.py android-app/storage.py
cp blind_store.py android-app/blind_store.py

echo "[OK] storage.py и blind_store.py скопированы в android-app/"
