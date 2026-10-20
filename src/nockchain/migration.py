"""Authenticated V0 input records for migration into V1 output seeds."""

from __future__ import annotations
from dataclasses import dataclass, field
from ._core import (
    Cell,
    Digest,
    Noun,
    NockchainError,
    atom,
    bounded_noun,
    fold_hashes,
    hash_atom,
    hash_cell,
    hash_noun,
    noun_digest,
    noun_tuple,
    parts,
)
from ._curve import parse_point
from ._tree import Tree, read_tree, tree_digest, tree_noun, tree_put
from .keys import public_noun
from .locks import NoteName, RequiredPkhPolicy, TimelockV1, _parse_range, _range_hash, _range_noun


def _public_bytes(noun: Noun) -> bytes:
    x, y, marker = parts(noun, 3)
    if marker != 1:
        raise NockchainError("invalid public point marker")
    value = b"\x01" + b"".join(
        atom(v).to_bytes(8, "big") for coordinate in (y, x) for v in reversed(parts(coordinate, 6))
    )
    parse_point(value)
    return value


@dataclass(frozen=True, slots=True)
class LockV0:
    threshold: int
    public_keys: tuple[bytes, ...]
    keys: tuple[Digest, ...] = field(init=False)
    root: Digest = field(init=False)
    _noun: Noun = field(init=False, repr=False)

    def __post_init__(self):
        public = tuple(bytes(key) for key in self.public_keys)
        if type(self.threshold) is not int or not 1 <= self.threshold <= len(public) <= 32:
            raise NockchainError("invalid migration signature threshold")
        nouns = tuple(public_noun(parse_point(key)) for key in public)
        keys = tuple(hash_noun(noun) for noun in nouns)
        if len(set(keys)) != len(keys):
            raise NockchainError("duplicate migration public key")
        tree = None
        for noun, key in zip(nouns, keys):
            tree = tree_put(tree, Tree.make(noun, 0, key, key, False))
        object.__setattr__(self, "public_keys", public)
        object.__setattr__(self, "keys", keys)
        object.__setattr__(self, "root", hash_cell(hash_atom(self.threshold), tree_digest(tree)))
        object.__setattr__(self, "_noun", Cell(self.threshold, tree_noun(tree)))

    def noun(self) -> Noun:
        return self._noun

    def required_pkh_policy(self) -> RequiredPkhPolicy:
        return RequiredPkhPolicy(self.threshold, self.keys)

    @classmethod
    def from_noun(cls, noun: Noun) -> LockV0:
        threshold, keyset = parts(noun, 2)
        keys = []

        def entry(key, _value):
            keys.append(_public_bytes(key))
            digest = hash_noun(key)
            return digest, digest

        read_tree(keyset, False, 32, entry)
        return cls(atom(threshold), tuple(keys))


def note_first_v0(lock: LockV0, has_timelock: bool = False) -> Digest:
    if not isinstance(lock, LockV0) or type(has_timelock) is not bool:
        raise NockchainError("invalid migration lock")
    return fold_hashes(hash_atom(0), hash_atom(0 if has_timelock else 1), lock.root, hash_atom(0))


@dataclass(frozen=True, slots=True)
class NoteV0:
    origin_page: int
    name: NoteName
    lock: LockV0
    source: Digest
    nicks: int
    timelock: TimelockV1 | None = None
    coinbase: bool = False

    def __post_init__(self):
        atom(self.origin_page)
        if (
            atom(self.nicks) == 0
            or not isinstance(self.name, NoteName)
            or not isinstance(self.lock, LockV0)
        ):
            raise NockchainError("invalid migration note")
        object.__setattr__(self, "source", Digest(self.source))
        if type(self.coinbase) is not bool:
            raise NockchainError("invalid coinbase flag")
        if self.timelock is not None:
            if not isinstance(self.timelock, TimelockV1) or all(
                value is None
                for value in (
                    self.timelock.absolute.min,
                    self.timelock.absolute.max,
                    self.timelock.relative.min,
                    self.timelock.relative.max,
                )
            ):
                raise NockchainError("empty migration timelock")

    def _time_noun(self) -> Noun:
        return (
            0
            if self.timelock is None
            else noun_tuple(
                0, _range_noun(self.timelock.absolute), _range_noun(self.timelock.relative)
            )
        )

    def noun(self) -> Noun:
        return noun_tuple(
            noun_tuple(0, self.origin_page, self._time_noun()),
            self.name.noun(),
            self.lock.noun(),
            Cell(self.source.noun(), 0 if self.coinbase else 1),
            self.nicks,
        )

    def hash(self) -> Digest:
        time = (
            hash_atom(0)
            if self.timelock is None
            else fold_hashes(
                hash_atom(0),
                _range_hash(self.timelock.absolute),
                _range_hash(self.timelock.relative),
            )
        )
        return hash_cell(
            fold_hashes(hash_atom(0), hash_atom(self.origin_page), time),
            fold_hashes(
                self.name.hash(),
                self.lock.root,
                hash_cell(self.source, hash_atom(0 if self.coinbase else 1)),
                hash_atom(self.nicks),
            ),
        )

    def admits(self, height: int | None) -> bool:
        return self.name.first == note_first_v0(self.lock, self.timelock is not None) and (
            self.timelock is None
            or (height is not None and self.timelock.allows(height, self.origin_page))
        )

    @classmethod
    def from_noun(cls, noun: Noun) -> NoteV0:
        bounded_noun(noun)
        meta, name, lock, source, nicks = parts(noun, 5)
        version, origin, time = parts(meta, 3)
        if version != 0:
            raise NockchainError("unsupported input version")
        first, last, zero = parts(name, 3)
        if zero != 0:
            raise NockchainError("invalid note name")
        source, coinbase = parts(source, 2)
        if coinbase not in (0, 1):
            raise NockchainError("invalid coinbase flag")
        timelock = None
        if time != 0:
            tag, absolute, relative = parts(time, 3)
            if tag != 0:
                raise NockchainError("invalid migration timelock")
            timelock = TimelockV1(_parse_range(relative), _parse_range(absolute))
        return cls(
            atom(origin),
            NoteName(noun_digest(first), noun_digest(last)),
            LockV0.from_noun(lock),
            noun_digest(source),
            atom(nicks),
            timelock,
            coinbase == 0,
        )
