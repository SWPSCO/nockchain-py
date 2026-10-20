"""Canonical metadata and typed lock, bridge deposit, and withdrawal payloads."""

from __future__ import annotations
from dataclasses import dataclass
from ._core import (
    PRIME,
    Cell,
    Digest,
    Noun,
    NockchainError,
    atom,
    bounded_noun,
    hash_atom,
    hash_cell,
    hash_each,
    leaf_count,
    noun_digest,
    noun_equal,
    noun_list,
    noun_tuple,
    parts,
)
from ._tree import Tree, metadata_entries, tree_digest, tree_noun, tree_put
from .lock_tree import LockFormV1, parse_lock


def _key(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or not value.strip():
        raise NockchainError("empty note-data key")
    value = value.strip()
    return value, atom(int.from_bytes(value.encode("utf-8"), "little"))


@dataclass(frozen=True, slots=True)
class LockData:
    lock: LockFormV1

    def noun(self) -> Noun:
        return Cell(0, self.lock.noun())

    @classmethod
    def from_noun(cls, noun: Noun) -> LockData:
        version, lock = parts(noun, 2)
        if version != 0:
            raise NockchainError("unsupported lock-data version")
        return cls(parse_lock(lock))


@dataclass(frozen=True, slots=True)
class BridgeDepositDataPayload:
    """A 20-byte big-endian EVM address, encoded as three little-endian base-p digits."""

    evm_address: bytes

    def __post_init__(self):
        if not isinstance(self.evm_address, bytes) or len(self.evm_address) != 20:
            raise NockchainError("EVM address must contain 20 bytes")

    def noun(self) -> Noun:
        value, digits = int.from_bytes(self.evm_address, "big"), []
        for _ in range(3):
            value, digit = divmod(value, PRIME)
            digits.append(digit)
        return noun_tuple(0, 0x65736162, *digits)

    @classmethod
    def from_noun(cls, noun: Noun) -> BridgeDepositDataPayload:
        version, network, a, b, c = parts(noun, 5)
        if version != 0 or network != 0x65736162:
            raise NockchainError("unsupported bridge version or network")
        address = atom(a) + PRIME * (atom(b) + PRIME * atom(c))
        if address >= 1 << 160:
            raise NockchainError("EVM address exceeds 160 bits")
        return cls(address.to_bytes(20, "big"))


@dataclass(frozen=True, slots=True)
class BridgeWithdrawalDataPayload:
    beid: tuple[int, ...]
    base_hash: Digest
    lock_root: Digest
    base_batch_end: int

    def __post_init__(self):
        object.__setattr__(self, "beid", tuple(atom(v) for v in self.beid))
        object.__setattr__(self, "base_hash", Digest(self.base_hash))
        object.__setattr__(self, "lock_root", Digest(self.lock_root))
        atom(self.base_batch_end)

    def noun(self) -> Noun:
        return noun_tuple(
            0,
            noun_list(*self.beid),
            self.base_hash.noun(),
            self.lock_root.noun(),
            self.base_batch_end,
        )

    @classmethod
    def from_noun(cls, noun: Noun) -> BridgeWithdrawalDataPayload:
        bounded_noun(noun)
        version, beid, base_hash, lock_root, end = parts(noun, 5)
        if version != 0:
            raise NockchainError("unsupported bridge withdrawal version")
        values = []
        while isinstance(beid, Cell):
            values.append(atom(beid.head))
            beid = beid.tail
        if beid != 0:
            raise NockchainError("invalid withdrawal beid")
        return cls(tuple(values), noun_digest(base_hash), noun_digest(lock_root), atom(end))


@dataclass(frozen=True, slots=True)
class DecodedNoteDataEntry:
    key: str
    payload: LockData | BridgeDepositDataPayload | BridgeWithdrawalDataPayload | Noun


@dataclass(frozen=True, slots=True)
class NoteData:
    """Normalized immutable metadata; unknown versions and networks remain raw nouns."""

    entries: tuple[tuple[str, Noun], ...] = ()

    def __post_init__(self):
        entries = {}
        for key, value in self.entries:
            key, _ = _key(key)
            bounded_noun(value)
            if key in entries and not noun_equal(entries[key], value):
                raise NockchainError("conflicting note-data values")
            entries[key] = value
        if len(entries) > 64:
            raise NockchainError("too many note-data entries")
        object.__setattr__(self, "entries", tuple(sorted(entries.items())))

    def _tree(self):
        tree = None
        for name, value in self.entries:
            _, key = _key(name)
            digest = hash_cell(hash_atom(key), hash_each(value))
            tree = tree_put(tree, Tree.make(key, value, digest, digest, True))
        return tree

    def noun(self) -> Noun:
        return tree_noun(self._tree())

    def hash(self) -> Digest:
        return tree_digest(self._tree())

    def words(self) -> int:
        return 1 + sum(1 + leaf_count(value) for _, value in self.entries)

    @classmethod
    def from_noun(cls, noun: Noun) -> NoteData:
        entries = []
        for key, value in metadata_entries(noun).items():
            try:
                name = key.to_bytes((key.bit_length() + 7) // 8, "little").decode("utf-8")
            except UnicodeError as error:
                raise NockchainError("invalid note-data key encoding") from error
            entries.append((name, value))
        return cls(tuple(entries))

    @classmethod
    def from_lock(cls, lock: LockFormV1) -> NoteData:
        return cls((("lock", LockData(lock).noun()),))

    def with_entry(self, key: str, payload) -> NoteData:
        key, _ = _key(key)
        value = payload.noun() if hasattr(payload, "noun") else payload
        return NoteData(tuple((k, v) for k, v in self.entries if k != key) + ((key, value),))

    def decoded(self) -> tuple[DecodedNoteDataEntry, ...]:
        types = {
            "lock": LockData,
            "bridge": BridgeDepositDataPayload,
            "bridge-w": BridgeWithdrawalDataPayload,
        }
        result = []
        for key, value in self.entries:
            payload = value
            if key in types:
                try:
                    payload = types[key].from_noun(value)
                except NockchainError:
                    pass
            result.append(DecodedNoteDataEntry(key, payload))
        return tuple(result)
