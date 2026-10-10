"""English BIP39 recovery with explicit exports and redacted diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
import unicodedata

from ._core import NockchainError
from ._english import WORDS
from .keys import ExtendedKey, master

_INDEX = {word: index for index, word in enumerate(WORDS)}


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryPhrase:
    _words: str

    def __repr__(self) -> str:
        return "Nockchain recovery phrase (redacted)"

    __str__ = __repr__

    def words(self) -> str:
        """Explicitly export the recovery secret for an offline backup."""
        return self._words


@dataclass(frozen=True, slots=True, repr=False)
class Seed:
    _data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self._data, (bytes, bytearray, memoryview)) or len(self._data) != 64:
            raise NockchainError("seed must contain 64 bytes")
        object.__setattr__(self, "_data", bytes(self._data))

    def __repr__(self) -> str:
        return "Nockchain seed (redacted)"

    __str__ = __repr__

    def to_bytes(self) -> bytes:
        """Explicitly export the raw seed. Treat it as spending authority."""
        return self._data

    def key(self) -> ExtendedKey:
        return master(self._data)


def generate_seed() -> Seed:
    return Seed(secrets.token_bytes(64))


def mnemonic_from_entropy(entropy: bytes) -> RecoveryPhrase:
    """Create a phrase from 128–256 bits of caller-supplied entropy."""
    if not isinstance(entropy, (bytes, bytearray, memoryview)) or len(entropy) not in (
        16,
        20,
        24,
        28,
        32,
    ):
        raise NockchainError("entropy must be 128 to 256 bits in 32-bit increments")
    entropy = bytes(entropy)
    checksum_bits = len(entropy) // 4
    bits = (int.from_bytes(entropy, "big") << checksum_bits) | (
        hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    )
    count = (len(entropy) * 8 + checksum_bits) // 11
    return RecoveryPhrase(
        " ".join(WORDS[(bits >> (11 * i)) & 2047] for i in reversed(range(count)))
    )


def generate_mnemonic() -> RecoveryPhrase:
    """Generate a 24-word recovery phrase using OS randomness."""
    return mnemonic_from_entropy(secrets.token_bytes(32))


def seed_from_mnemonic(phrase: str, passphrase: str = "") -> Seed:
    """Validate checksum and apply BIP39 NFKD normalization and PBKDF2."""
    if (
        not isinstance(phrase, str)
        or not isinstance(passphrase, str)
        or len(phrase.encode()) > 1024
        or len(passphrase.encode()) > 4096
    ):
        raise NockchainError("invalid or oversized mnemonic/passphrase")
    words = unicodedata.normalize("NFKD", phrase).split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise NockchainError("invalid BIP39 word count")
    bits = 0
    for word in words:
        if word not in _INDEX:
            raise NockchainError("invalid English BIP39 word")
        bits = (bits << 11) | _INDEX[word]
    entropy_size = len(words) * 11 * 32 // 33 // 8
    checksum_bits = entropy_size // 4
    entropy = (bits >> checksum_bits).to_bytes(entropy_size, "big")
    if bits & ((1 << checksum_bits) - 1) != hashlib.sha256(entropy).digest()[0] >> (
        8 - checksum_bits
    ):
        raise NockchainError("invalid BIP39 checksum")
    normalized = " ".join(words).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return Seed(hashlib.pbkdf2_hmac("sha512", normalized, salt, 2048, 64))


def restore_wallet(phrase: str, passphrase: str = "") -> ExtendedKey:
    """A wrong passphrase produces a different valid wallet."""
    return seed_from_mnemonic(phrase, passphrase).key()


def generate_wallet(passphrase: str = "") -> tuple[ExtendedKey, RecoveryPhrase]:
    phrase = generate_mnemonic()
    return restore_wallet(phrase.words(), passphrase), phrase
