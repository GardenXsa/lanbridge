"""
Модуль шифрования LanBridge.
Использует ChaCha20-Poly1305 для быстрого и безопасного шифрования.
"""

import os
import struct
import hashlib
from typing import Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class CryptoEngine:
    """Движок шифрования на основе ChaCha20-Poly1305."""

    NONCE_SIZE = 12  # 96 бит для ChaCha20-Poly1305
    KEY_SIZE = 32    # 256 бит
    SALT_SIZE = 16
    KDF_ITERATIONS = 100_000

    def __init__(self, password: str, salt: bytes = None):
        if not HAS_CRYPTO:
            raise RuntimeError(
                "Библиотека 'cryptography' не установлена.\n"
                "Установите: pip install cryptography"
            )
        self.salt = salt or os.urandom(self.SALT_SIZE)
        self._key = self._derive_key(password, self.salt)
        self._cipher = ChaCha20Poly1305(self._key)
        # Счётчик nonce — увеличивается с каждым пакетом для уникальности
        self._send_counter = 0
        self._recv_counter = 0

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Производная ключа из пароля через PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    def _nonce_from_counter(self, counter: int) -> bytes:
        """Генерирует nonce из счётчика (12 байт)."""
        # 4 байта нули + 8 байт счётчик
        return b'\x00' * 4 + struct.pack('>Q', counter)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Шифрует данные. Возвращает salt + nonce_counter + ciphertext + tag."""
        nonce = self._nonce_from_counter(self._send_counter)
        self._send_counter += 1
        ciphertext = self._cipher.encrypt(nonce, plaintext, None)
        # Формат: [salt(16)] [counter(8)] [ciphertext+tag]
        return self.salt + struct.pack('>Q', self._send_counter - 1) + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Расшифровывает данные."""
        if len(data) < self.SALT_SIZE + 8:
            raise ValueError("Пакет слишком короткий для расшифровки")

        salt = data[:self.SALT_SIZE]
        counter = struct.unpack('>Q', data[self.SALT_SIZE:self.SALT_SIZE + 8])[0]
        ciphertext = data[self.SALT_SIZE + 8:]

        # Если salt отличается — пересоздаём ключ (для начального пакета)
        if salt != self.salt:
            self.salt = salt
            self._key = self._derive_key_from_salt(salt)
            self._cipher = ChaCha20Poly1305(self._key)

        nonce = self._nonce_from_counter(counter)
        return self._cipher.decrypt(nonce, ciphertext, None)

    def _derive_key_from_salt(self, salt: bytes) -> bytes:
        """Derive a new key when salt changes during decryption."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
        )
        return kdf.derive(self._key)  # Use current key as material

    def get_salt(self) -> bytes:
        """Возвращает текущий salt для передачи партнёру."""
        return self.salt


class SimpleXOR:
    """
    Простая замена шифрованию на случай, если cryptography недоступна.
    НЕ обеспечивает настоящую безопасность, но работает быстро.
    Используется только как fallback.
    """

    def __init__(self, password: str):
        key = hashlib.sha256(password.encode('utf-8')).digest()
        # Расширяем ключ до 256 байт для лучшего перемешивания
        self._key = (key * 8)

    def encrypt(self, plaintext: bytes) -> bytes:
        """XOR-шифрование (только для fallback)."""
        key = self._key
        key_len = len(key)
        result = bytearray(len(plaintext))
        for i, b in enumerate(plaintext):
            result[i] = b ^ key[i % key_len]
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """XOR-расшифровка (симметрична шифрованию)."""
        return self.encrypt(data)

    def get_salt(self) -> bytes:
        return b'\x00' * 16


def create_crypto(password: str, salt: bytes = None):
    """Фабрика: создаёт CryptoEngine или SimpleXOR."""
    if HAS_CRYPTO:
        return CryptoEngine(password, salt)
    else:
        print("[!] Библиотека 'cryptography' не найдена. Используется простой XOR (НЕ безопасно!)")
        print("[!] Установите: pip install cryptography")
        return SimpleXOR(password)
