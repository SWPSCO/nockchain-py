"""Full PKH lock policies, inclusive timelocks, and complete note commitments."""

from __future__ import annotations
from dataclasses import dataclass, field

from ._core import (
    Cell,
    Digest,
    Noun,
    NockchainError,
    atom,
    fold_hashes,
    hash_atom,
    hash_cell,
    noun_digest,
    noun_list,
    noun_tuple,
    parts,
)
from ._tree import Tree, metadata_hash, read_tree, tree_digest, tree_noun, tree_put


@dataclass(frozen=True, slots=True)
class HeightRange:
    min: int | None = None
    max: int | None = None

    def __post_init__(self) -> None:
        if self.min is not None:
            atom(self.min)
        if self.max is not None:
            atom(self.max)
        if self.min is not None and self.max is not None and self.min > self.max:
            raise NockchainError("inverted height range")

    def contains(self, height: int) -> bool:
        return (self.min is None or height >= self.min) and (self.max is None or height <= self.max)


@dataclass(frozen=True, slots=True)
class TimelockV1:
    relative: HeightRange = field(default_factory=HeightRange)
    absolute: HeightRange = field(default_factory=HeightRange)

    def __post_init__(self) -> None:
        if not isinstance(self.relative, HeightRange) or not isinstance(self.absolute, HeightRange):
            raise NockchainError("invalid timelock ranges")

    def allows(self, height: int, origin: int) -> bool:
        atom(height)
        atom(origin)
        return (
            origin <= height
            and self.absolute.contains(height)
            and self.relative.contains(height - origin)
        )


def _optional(value: int | None) -> Noun:
    return 0 if value is None else Cell(0, value)


def _optional_hash(value: int | None) -> Digest:
    return hash_atom(0) if value is None else hash_cell(hash_atom(0), hash_atom(value))


def _range_noun(value: HeightRange) -> Noun:
    return Cell(_optional(value.min), _optional(value.max))


def _range_hash(value: HeightRange) -> Digest:
    return hash_cell(_optional_hash(value.min), _optional_hash(value.max))


@dataclass(frozen=True, slots=True)
class LockV1:
    """Immutable m-of-n PKH policy with an optional conjunctive timelock."""

    threshold: int
    keys: tuple[Digest, ...]
    timelock: TimelockV1 | None = None
    root: Digest = field(init=False)
    _condition: Noun = field(init=False, repr=False)

    def __post_init__(self) -> None:
        keys = tuple(Digest(key) for key in self.keys)
        if (
            type(self.threshold) is not int
            or not 1 <= self.threshold <= len(keys) <= 32
            or len(set(keys)) != len(keys)
        ):
            raise NockchainError("invalid signature threshold or duplicate keys")
        if self.timelock is not None and not isinstance(self.timelock, TimelockV1):
            raise NockchainError("invalid timelock")
        tree = None
        for key in keys:
            tree = tree_put(tree, Tree.make(key.noun(), 0, key, key, False))
        pkh = noun_tuple(0x686B70, self.threshold, tree_noun(tree))
        tail, tail_hash = 0, hash_atom(0)
        if self.timelock is not None:
            time = self.timelock
            primitive = noun_tuple(0x6D6974, _range_noun(time.relative), _range_noun(time.absolute))
            tail = noun_list(primitive)
            tail_hash = hash_cell(
                fold_hashes(
                    hash_atom(0x6D6974), _range_hash(time.relative), _range_hash(time.absolute)
                ),
                tail_hash,
            )
        root = hash_cell(
            fold_hashes(hash_atom(0x686B70), hash_atom(self.threshold), tree_digest(tree)),
            tail_hash,
        )
        object.__setattr__(self, "keys", keys)
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "_condition", Cell(pkh, tail))

    def metadata(self) -> Noun:
        value = Cell(0, self._condition)
        from ._core import hash_each

        digest = hash_cell(hash_atom(0x6B636F6C), hash_each(value))
        return tree_noun(Tree.make(0x6B636F6C, value, digest, digest, True))

    def _proof(self) -> Noun:
        return noun_tuple(0x6C6C7566, self._condition, 1, Cell(self.root.noun(), 0))

    def _proof_hash(self) -> Digest:
        return fold_hashes(
            hash_atom(0x6C6C7566), self.root, hash_atom(1), hash_cell(self.root, hash_atom(0))
        )


def new_pkh_lock_v1(threshold: int, keys, timelock: TimelockV1 | None = None) -> LockV1:
    return LockV1(threshold, tuple(keys), timelock)


def note_first_v1(lock_root: Digest) -> Digest:
    return hash_cell(hash_atom(0), Digest(lock_root))


@dataclass(frozen=True, slots=True)
class NoteName:
    first: Digest
    last: Digest

    def __post_init__(self) -> None:
        object.__setattr__(self, "first", Digest(self.first))
        object.__setattr__(self, "last", Digest(self.last))

    def noun(self) -> Noun:
        return noun_list(self.first.noun(), self.last.noun())

    def hash(self) -> Digest:
        return hash_cell(self.first, hash_cell(self.last, hash_atom(0)))


@dataclass(frozen=True, slots=True)
class NoteV1:
    """Complete authenticated input record; callers establish existence/unspent status."""

    origin_page: int
    name: NoteName
    note_data: Noun
    nicks: int

    def __post_init__(self) -> None:
        atom(self.origin_page)
        atom(self.nicks)
        if self.nicks == 0 or not isinstance(self.name, NoteName):
            raise NockchainError("invalid note record")
        metadata_hash(self.note_data)

    def hash(self) -> Digest:
        return fold_hashes(
            hash_atom(1),
            hash_atom(self.origin_page),
            self.name.hash(),
            metadata_hash(self.note_data),
            hash_atom(self.nicks),
        )


def _parse_optional(noun: Noun) -> int | None:
    if noun == 0:
        return None
    tag, value = parts(noun, 2)
    if tag != 0:
        raise NockchainError("invalid optional height")
    return atom(value)


def _parse_range(noun: Noun) -> HeightRange:
    low, high = parts(noun, 2)
    return HeightRange(_parse_optional(low), _parse_optional(high))


def parse_condition(noun: Noun) -> LockV1:
    if not isinstance(noun, Cell):
        raise NockchainError("unsupported lock condition")
    tag, threshold, keyset = parts(noun.head, 3)
    if tag != 0x686B70:
        raise NockchainError("unsupported lock primitive")
    threshold = atom(threshold)
    keys = []

    def entry(key: Noun, value: Noun) -> tuple[Digest, Digest]:
        digest = noun_digest(key)
        keys.append(digest)
        return digest, digest

    read_tree(keyset, False, 32, entry)
    time = None
    tail = noun.tail
    if tail != 0:
        if not isinstance(tail, Cell) or tail.tail != 0:
            raise NockchainError("unsupported lock condition")
        tag, relative, absolute = parts(tail.head, 3)
        if tag != 0x6D6974:
            raise NockchainError("unsupported lock primitive")
        time = TimelockV1(_parse_range(relative), _parse_range(absolute))
    return LockV1(threshold, tuple(keys), time)
