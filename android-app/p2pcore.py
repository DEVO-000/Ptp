"""Крипто-ядро мобильного приложения: БЕЗ libp2p (в APK он не входит).

Совместимость с CLI-версией (identity.py, crypto.py) побайтовая:
  - тот же профиль identity.json (BIP39-фраза, версия 1, права 0600);
  - те же строки HKDF-info → те же ключи из той же фразы;
  - тот же бинарный конверт E2EE v1 и тот же формат подписанных анонсов.

Отличается ровно одно: строка Peer ID. В CLI её считает libp2p
(ID.from_pubkey), здесь она выводится самостоятельно по канону libp2p:
protobuf PublicKey{Type=Ed25519, Data} -> identity-multihash -> base58btc.
Это кодирование байтов (как hex), а не криптография; совпадение с libp2p
проверяется кросс-тестом tests/test_app_net.py.

Вся криптография — только библиотека `cryptography` (OpenSSL):
Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305. Самописной криптографии нет.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mnemonic import Mnemonic

IDENTITY_FILE = "identity.json"
IDENTITY_VERSION = 1

_ED25519_INFO = b"p2p-messenger/ed25519-signing-key/v1"
_X25519_INFO = b"p2p-messenger/x25519-encryption-key/v1"
_HKDF_INFO = b"p2p-messenger/e2ee/v1"
_ANNOUNCE_CANONICAL = "key-announce/v1"

# --- конверт E2EE v1 (идентично crypto.py) -----------------------------------

VERSION = 1
NONCE_LEN = 12
KEY_LEN = 32
PUB_LEN = 32
SIG_LEN = 64
HEADER_LEN = 1 + PUB_LEN + PUB_LEN + NONCE_LEN  # 77
MIN_ENVELOPE_LEN = HEADER_LEN + SIG_LEN + 16


class IdentityError(Exception):
    """Ошибка работы с идентичностью (невалидная фраза, профиль и т.п.)."""


class CryptoError(Exception):
    """Ошибка расшифрования/проверки конверта или анонса."""


# --- Peer ID: protobuf -> identity-multihash -> base58btc --------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    """Base58btc (биткойн-алфавит) — только кодирование байтов, не крипто."""
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    for b in data:  # ведущие нулевые байты -> '1'
        if b == 0:
            out.append("1")
        else:
            break
    return "".join(reversed(out))


def _varint(n: int) -> bytes:
    out = []
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def peer_id_from_ed25519_raw(ed25519_pub_raw: bytes) -> str:
    """Peer ID = identity-multihash(protobuf-кодировки Ed25519 pubkey).

    Канон libp2p: PublicKey{Type=Ed25519(1), Data=raw 32} сериализуется как
    0x08 0x01 0x12 <len> <data>, оборачивается в identity-multihash
    (0x00 <varint len> <data>) и кодируется base58btc.
    """
    if len(ed25519_pub_raw) != PUB_LEN:
        raise CryptoError("некорректная длина Ed25519 pubkey")
    protobuf = b"\x08\x01\x12" + _varint(len(ed25519_pub_raw)) + ed25519_pub_raw
    multihash = b"\x00" + _varint(len(protobuf)) + protobuf
    return _b58encode(multihash)


# --- подписи (тонкие обёртки над `cryptography`) ------------------------------


def sign(ed25519_seed: bytes, data: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(ed25519_seed).sign(data)


def verify_ed25519(ed25519_pub_raw: bytes, signature: bytes, data: bytes) -> None:
    """Бросает CryptoError, если подпись неверна."""
    try:
        Ed25519PublicKey.from_public_bytes(ed25519_pub_raw).verify(signature, data)
    except InvalidSignature as exc:
        raise CryptoError("подпись Ed25519 неверна") from exc


# --- конверт E2EE ---------------------------------------------------------------


def _derive_key(shared_secret: bytes, nonce: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=nonce,
        info=_HKDF_INFO,
    ).derive(shared_secret)


def encrypt_message(
    sender_ed25519_seed: bytes,
    sender_x25519_seed: bytes,
    recipient_x25519_pub_raw: bytes,
    plaintext: bytes,
) -> bytes:
    """X25519 ECDH -> HKDF(salt=nonce) -> ChaCha20-Poly1305 + подпись Ed25519."""
    if len(recipient_x25519_pub_raw) != PUB_LEN:
        raise CryptoError("некорректная длина X25519 pubkey получателя")

    sender_ed = Ed25519PrivateKey.from_private_bytes(sender_ed25519_seed)
    sender_x = X25519PrivateKey.from_private_bytes(sender_x25519_seed)
    recipient_x_pub = X25519PublicKey.from_public_bytes(recipient_x25519_pub_raw)

    nonce = os.urandom(NONCE_LEN)
    shared = sender_x.exchange(recipient_x_pub)
    key = _derive_key(shared, nonce)

    header = (
        bytes([VERSION])
        + sender_ed.public_key().public_bytes_raw()
        + sender_x.public_key().public_bytes_raw()
        + nonce
    )
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)

    unsigned = header + ciphertext
    signature = sender_ed.sign(unsigned)
    return unsigned + signature


def decrypt_message(
    recipient_x25519_seed: bytes, envelope: bytes
) -> tuple[str, str, bytes]:
    """-> (peer_id отправителя, x25519_pub отправителя b64, plaintext)."""
    if len(envelope) < MIN_ENVELOPE_LEN:
        raise CryptoError("конверт слишком короткий")
    if envelope[0] != VERSION:
        raise CryptoError(f"неизвестная версия конверта: {envelope[0]}")

    unsigned, signature = envelope[:-SIG_LEN], envelope[-SIG_LEN:]
    header, ciphertext = unsigned[:HEADER_LEN], unsigned[HEADER_LEN:]
    sender_ed_pub_raw = header[1 : 1 + PUB_LEN]
    sender_x_pub_raw = header[1 + PUB_LEN : 1 + 2 * PUB_LEN]
    nonce = header[1 + 2 * PUB_LEN : HEADER_LEN]

    verify_ed25519(sender_ed_pub_raw, signature, unsigned)

    recipient_x = X25519PrivateKey.from_private_bytes(recipient_x25519_seed)
    shared = recipient_x.exchange(X25519PublicKey.from_public_bytes(sender_x_pub_raw))
    key = _derive_key(shared, nonce)
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise CryptoError(
            "расшифрование не удалось (конверт не нам либо повреждён)"
        ) from exc

    sender_peer_id = peer_id_from_ed25519_raw(sender_ed_pub_raw)
    sender_x_b64 = base64.b64encode(sender_x_pub_raw).decode("ascii")
    return sender_peer_id, sender_x_b64, plaintext


# --- анонс публичных ключей (открытые данные) ----------------------------------


def make_key_announcement(
    sender_ed25519_seed: bytes, sender_x25519_pub_raw: bytes, nick: str
) -> dict:
    sender_ed = Ed25519PrivateKey.from_private_bytes(sender_ed25519_seed)
    ed_pub_raw = sender_ed.public_key().public_bytes_raw()
    peer_id = peer_id_from_ed25519_raw(ed_pub_raw)
    ed_b64 = base64.b64encode(ed_pub_raw).decode("ascii")
    x_b64 = base64.b64encode(sender_x25519_pub_raw).decode("ascii")
    payload = f"{_ANNOUNCE_CANONICAL}|{peer_id}|{ed_b64}|{x_b64}"
    sig = base64.b64encode(sign(sender_ed25519_seed, payload.encode("utf-8"))).decode(
        "ascii"
    )
    return {
        "type": "key-announce",
        "peer_id": peer_id,
        "ed25519_pub": ed_b64,
        "x25519_pub": x_b64,
        "nick": nick,
        "sig": sig,
    }


def verify_key_announcement(announce: dict) -> tuple[str, str, bytes]:
    """-> (peer_id, nick, x25519_pub_raw); CryptoError, если анонс плохой."""
    try:
        peer_id = str(announce["peer_id"])
        ed_b64 = str(announce["ed25519_pub"])
        x_b64 = str(announce["x25519_pub"])
        nick = str(announce.get("nick", "?"))
        sig = base64.b64decode(str(announce["sig"]))
        ed_pub_raw = base64.b64decode(ed_b64)
        x_pub_raw = base64.b64decode(x_b64)
    except (KeyError, ValueError) as exc:
        raise CryptoError(f"некорректный формат анонса: {exc}") from exc

    if len(ed_pub_raw) != PUB_LEN or len(x_pub_raw) != PUB_LEN or len(sig) != SIG_LEN:
        raise CryptoError("некорректные длины ключей в анонсе")

    payload = f"{_ANNOUNCE_CANONICAL}|{peer_id}|{ed_b64}|{x_b64}"
    verify_ed25519(ed_pub_raw, sig, payload.encode("utf-8"))
    if peer_id_from_ed25519_raw(ed_pub_raw) != peer_id:
        raise CryptoError("peer_id не соответствует приложенному ключу")

    return peer_id, nick, x_pub_raw


# --- идентичность -------------------------------------------------------------


def _hkdf32(bip39_seed: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
        bip39_seed
    )


@dataclass(frozen=True)
class Identity:
    """Идентичность узла без libp2p: те же ключи, что и в CLI-версии."""

    mnemonic: tuple[str, ...]
    ed25519_seed: bytes  # raw 32 байта приватного Ed25519
    x25519_seed: bytes  # raw 32 байта приватного X25519
    x25519_pub: bytes  # raw 32 байта публичного X25519

    @property
    def mnemonic_str(self) -> str:
        return " ".join(self.mnemonic)

    @property
    def peer_id(self) -> str:
        return peer_id_from_ed25519_raw(self.ed25519_pub_raw)

    @property
    def ed25519_pub_raw(self) -> bytes:
        return (
            Ed25519PrivateKey.from_private_bytes(self.ed25519_seed)
            .public_key()
            .public_bytes_raw()
        )

    @property
    def ed25519_pub_b64(self) -> str:
        return base64.b64encode(self.ed25519_pub_raw).decode("ascii")

    @property
    def x25519_pub_b64(self) -> str:
        return base64.b64encode(self.x25519_pub).decode("ascii")


def _identity_from_mnemonic_str(mnemonic_str: str) -> Identity:
    words = mnemonic_str.lower().split()
    if len(words) != 24:
        raise IdentityError(
            f"seed-фраза должна состоять из 24 слов, получено {len(words)}"
        )
    m = Mnemonic("english")
    if not m.check(" ".join(words)):
        raise IdentityError("невалидная seed-фраза (не прошла проверку BIP39)")
    bip39_seed = m.to_seed(" ".join(words), passphrase="")

    ed_seed = _hkdf32(bip39_seed, _ED25519_INFO)
    x_seed = _hkdf32(bip39_seed, _X25519_INFO)
    return Identity(
        mnemonic=tuple(words),
        ed25519_seed=ed_seed,
        x25519_seed=x_seed,
        x25519_pub=X25519PrivateKey.from_private_bytes(x_seed)
        .public_key()
        .public_bytes_raw(),
    )


def generate_identity() -> Identity:
    """24 случайных слова BIP39 (256 бит энтропии) — как в CLI."""
    return _identity_from_mnemonic_str(Mnemonic("english").generate(strength=256))


def identity_from_mnemonic(mnemonic_str: str) -> Identity:
    return _identity_from_mnemonic_str(mnemonic_str)


# --- профиль на диске (формат identity.json тот же, что в CLI) ----------------


def identity_path(profile_dir: str | Path) -> Path:
    return Path(profile_dir) / IDENTITY_FILE


def identity_exists(profile_dir: str | Path) -> bool:
    return identity_path(profile_dir).is_file()


def save_identity(profile_dir: str | Path, identity: Identity) -> Path:
    path = identity_path(profile_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": IDENTITY_VERSION,
        "mnemonic": identity.mnemonic_str,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600: только владелец
    return path


def load_identity(profile_dir: str | Path) -> Identity:
    path = identity_path(profile_dir)
    if not path.is_file():
        raise IdentityError(f"профиль не найден: {path}")
    data = json.loads(path.read_text())
    if data.get("version") != IDENTITY_VERSION:
        raise IdentityError(f"неподдерживаемая версия профиля: {data.get('version')}")
    return identity_from_mnemonic(data["mnemonic"])
