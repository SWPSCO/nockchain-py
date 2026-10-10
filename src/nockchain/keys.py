"""Cheetah SLIP-10 keys, public receiving branches, and Schnorr signatures."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets

from ._core import (
    Cell,
    Digest,
    NockchainError,
    Noun,
    PRIME,
    decode_base58,
    encode_base58,
    hash_atom,
    hash_cell,
    hash_noun,
    hash_words,
    integer,
    noun_tuple,
)
from ._curve import GENERATOR, ORDER, ZERO, Point, parse_point


def public_noun(point: Point) -> Noun:
    p = point.affine()
    return noun_tuple(noun_tuple(*p.x), noun_tuple(*p.y), 1)


def public_key_hash(point: Point) -> Digest:
    return hash_noun(public_noun(point))


def lock_root(pkh: Digest) -> Digest:
    """The full 1-of-1 PKH lock root for an address digest."""
    pkh = Digest(pkh)
    nil = hash_atom(0)
    tree = hash_cell(pkh, hash_cell(nil, nil))
    return hash_cell(hash_cell(hash_atom(0x686B70), hash_cell(hash_atom(1), tree)), nil)


def _checksum(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha512")


def _limbs(value: int) -> tuple[int, ...]:
    return tuple((value >> (32 * i)) & 0xFFFFFFFF for i in range(8))


def _scalar(limbs: tuple[int, ...]) -> int:
    return sum(v << (32 * i) for i, v in enumerate(limbs))


def _digest_scalar(digest: Digest) -> int:
    return sum(digest[i] * PRIME**i for i in range(4)) % ORDER


def _point_words(p: Point) -> tuple[int, ...]:
    p = p.affine()
    return (*p.x, *p.y)


@dataclass(frozen=True, slots=True)
class Signature:
    """Schnorr challenge and response as eight little-endian uint32 limbs each."""

    challenge: tuple[int, ...]
    response: tuple[int, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "challenge", tuple(self.challenge))
        object.__setattr__(self, "response", tuple(self.response))
        for values in (self.challenge, self.response):
            if len(values) != 8:
                raise NockchainError("signature scalar requires eight limbs")
            for value in values:
                integer(value, 0xFFFFFFFF, "signature limb")

    def noun(self) -> Noun:
        return Cell(noun_tuple(*self.challenge), noun_tuple(*self.response))

    def _valid(self) -> bool:
        return 0 < _scalar(self.challenge) < ORDER and 0 < _scalar(self.response) < ORDER


_KEY_TOKEN = object()


class ExtendedKey:
    """Immutable V1 extended key. Diagnostic output redacts all key material."""

    __slots__ = ("_secret", "_pub", "_chain", "_depth", "_index", "_parent")

    def __init__(
        self,
        token: object,
        secret: bytes | None,
        pub: Point,
        chain: bytes,
        depth: int = 0,
        index: int = 0,
        parent: bytes = b"\0" * 4,
    ):
        if token is not _KEY_TOKEN:
            raise NockchainError("use master or parse_extended_key")
        for name, value in (
            ("_secret", secret),
            ("_pub", pub),
            ("_chain", chain),
            ("_depth", depth),
            ("_index", index),
            ("_parent", parent),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("extended keys are immutable")

    def __repr__(self) -> str:
        return "Nockchain key (private)" if self.is_private else "Nockchain key (public)"

    __str__ = __repr__

    @property
    def is_private(self) -> bool:
        return self._secret is not None

    def public(self) -> ExtendedKey:
        return ExtendedKey(
            _KEY_TOKEN, None, self._pub, self._chain, self._depth, self._index, self._parent
        )

    def public_bytes(self) -> bytes:
        return self._pub.to_bytes()

    def address(self) -> str:
        return str(public_key_hash(self._pub))

    def lock_address(self) -> str:
        return str(lock_root(public_key_hash(self._pub)))

    def child(self, index: int) -> ExtendedKey:
        integer(index, 0xFFFFFFFF, "child index")
        if self._depth == 255:
            raise NockchainError("derivation depth exceeds 255")
        index_bytes = index.to_bytes(4, "big")
        if index >= 1 << 31:
            if self._secret is None:
                raise NockchainError("hardened child requires private key")
            data = b"\0" + self._secret
        else:
            data = self.public_bytes()
        data += index_bytes
        for _ in range(1024):
            material = _hmac(self._chain, data)
            scalar = int.from_bytes(material[:32], "big")
            if 0 < scalar < ORDER:
                secret = None
                if self._secret is not None:
                    scalar = (scalar + int.from_bytes(self._secret, "big")) % ORDER
                    point = GENERATOR.times(scalar).affine()
                    secret = scalar.to_bytes(32, "big")
                else:
                    point = self._pub.plus(GENERATOR.times(scalar)).affine()
                if point.z != ZERO:
                    fingerprint = hash_words(_point_words(self._pub))[0].to_bytes(8, "big")[:4]
                    return ExtendedKey(
                        _KEY_TOKEN,
                        secret,
                        point,
                        material[32:],
                        self._depth + 1,
                        index,
                        fingerprint,
                    )
            data = b"\x01" + material[32:] + index_bytes
        raise NockchainError("child derivation failed")

    def derive(self, path: str) -> ExtendedKey:
        """Follow m/... components relative to this key; apostrophes harden indices."""
        if not isinstance(path, str) or len(path) > 4096:
            raise NockchainError("invalid derivation path")
        components = path.split("/")
        if components[0] != "m":
            raise NockchainError("derivation path must begin with m")
        result = self
        for component in components[1:]:
            if not re.fullmatch(r"(0|[1-9][0-9]*)'?", component):
                raise NockchainError("invalid derivation index")
            hard = component.endswith("'")
            value = int(component[:-1] if hard else component)
            integer(value, (1 << 31) - 1, "derivation index")
            result = result.child(value | ((1 << 31) if hard else 0))
        return result

    def _serialize(self, private: bool) -> str:
        prefix = 0x0C0EBB09
        data = self.public_bytes()
        if private:
            if self._secret is None:
                raise NockchainError("private key is unavailable")
            prefix, data = 0x01106331, b"\0" + self._secret
        payload = (
            prefix.to_bytes(4, "big")
            + bytes((1, self._depth))
            + self._parent
            + self._index.to_bytes(4, "big")
            + self._chain
            + data
        )
        return encode_base58(payload + _checksum(payload))

    def zpub(self) -> str:
        return self._serialize(False)

    def zprv(self) -> str:
        """Explicitly export spending authority for offline recovery."""
        return self._serialize(True)

    def sign_digest(self, message: Digest) -> Signature:
        """Create a deterministic secret-bound signature; arithmetic is variable-time."""
        message = Digest(message)
        if self._secret is None:
            raise NockchainError("private signing key required")
        secret = int.from_bytes(self._secret, "big")
        nonce = _digest_scalar(hash_words((*_point_words(self._pub), *message, *_limbs(secret))))
        if not nonce:
            raise NockchainError("zero signing nonce")
        challenge = _digest_scalar(
            hash_words((*_point_words(GENERATOR.times(nonce)), *_point_words(self._pub), *message))
        )
        response = (nonce + challenge * secret) % ORDER
        if not challenge or not response:
            raise NockchainError("zero signature scalar")
        return Signature(_limbs(challenge), _limbs(response))

    def sign_transfer_v1(self, plans):
        """Build and sign explicit single-key input allocations."""
        from .wallet import sign_transfer_v1

        return sign_transfer_v1(self, plans)


def master(seed: bytes) -> ExtendedKey:
    """Derive a private V1 master from exactly 64 bytes."""
    if not isinstance(seed, (bytes, bytearray, memoryview)) or len(seed) != 64:
        raise NockchainError("Nockchain seed must contain 64 bytes")
    material = _hmac(b"Nockchain seed", bytes(seed))
    for _ in range(1024):
        scalar = int.from_bytes(material[:32], "big")
        if 0 < scalar < ORDER:
            return ExtendedKey(
                _KEY_TOKEN, material[:32], GENERATOR.times(scalar).affine(), material[32:]
            )
        material = _hmac(b"Nockchain seed", material)
    raise NockchainError("master derivation failed")


def generate() -> ExtendedKey:
    """Create a private wallet; export its zprv privately before receiving funds."""
    return master(secrets.token_bytes(64))


def parse_extended_key(text: str) -> ExtendedKey:
    if not isinstance(text, str) or not 1 <= len(text) <= 210:
        raise NockchainError("invalid extended key length")
    encoded = decode_base58(text)
    if len(encoded) not in (83, 147):
        raise NockchainError("invalid extended key length")
    payload = encoded[:-4]
    if (
        encode_base58(encoded) != text
        or not hmac.compare_digest(encoded[-4:], _checksum(payload))
        or payload[4] != 1
    ):
        raise NockchainError("invalid V1 extended key")
    prefix = int.from_bytes(payload[:4], "big")
    depth, parent, index, chain = (
        payload[5],
        payload[6:10],
        int.from_bytes(payload[10:14], "big"),
        payload[14:46],
    )
    if depth == 0 and (index != 0 or parent != b"\0" * 4):
        raise NockchainError("invalid master metadata")
    secret = None
    if prefix == 0x01106331 and len(payload) == 79 and payload[46] == 0:
        secret = payload[47:]
        scalar = int.from_bytes(secret, "big")
        if not 0 < scalar < ORDER:
            raise NockchainError("invalid private scalar")
        point = GENERATOR.times(scalar).affine()
    elif prefix == 0x0C0EBB09 and len(payload) == 143:
        point = parse_point(payload[46:])
    else:
        raise NockchainError("invalid extended key type")
    return ExtendedKey(_KEY_TOKEN, secret, point, chain, depth, index, parent)


def parse_public_key(text: str) -> ExtendedKey:
    key = parse_extended_key(text)
    if key.is_private:
        raise NockchainError("watch-only configuration requires a zpub")
    return key


def verify_digest(public: bytes, message: Digest, signature: Signature) -> bool:
    """Strictly verify public point, scalar ranges and the Schnorr transcript."""
    try:
        message = Digest(message)
        if not isinstance(signature, Signature) or not signature._valid():
            return False
        point = parse_point(public)
        challenge, response = _scalar(signature.challenge), _scalar(signature.response)
        r = GENERATOR.times(response).plus(point.times(ORDER - challenge)).affine()
        if r.z == ZERO:
            return False
        return (
            _digest_scalar(hash_words((*_point_words(r), *_point_words(point), *message)))
            == challenge
        )
    except (ValueError, TypeError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class ReceiveAddress:
    index: int
    address: str
    lock_root: str


def derive_receive_address(zpub: str, index: int) -> ReceiveAddress:
    child = parse_public_key(zpub).child(index)
    return ReceiveAddress(index, child.address(), child.lock_address())
