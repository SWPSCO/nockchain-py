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
class RequiredPkhPolicy:
    threshold: int
    keys: tuple[Digest, ...]


@dataclass(frozen=True, slots=True)
class LockV1:
    """One conjunctive spend condition. Use LockTreeV1 for alternative conditions."""

    threshold: int
    keys: tuple[Digest, ...]
    timelock: TimelockV1 | None = None
    hashes: tuple[Digest, ...] = ()
    root: Digest = field(init=False)
    _condition: Noun = field(init=False, repr=False)
    _times: tuple[TimelockV1, ...] = field(init=False, repr=False)
    _policies: tuple[RequiredPkhPolicy, ...] = field(init=False, repr=False)
    _burn: bool = field(init=False, repr=False)

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
        primitives = [noun_tuple(0x686B70, self.threshold, _digest_set(keys))]
        if self.timelock is not None:
            primitives.append(
                noun_tuple(
                    0x6D6974,
                    _range_noun(self.timelock.relative),
                    _range_noun(self.timelock.absolute),
                )
            )
        if self.hashes:
            primitives.append(Cell(0x786168, _digest_set(self.hashes)))
        self._initialize(noun_list(*primitives))

    def _initialize(self, noun: Noun) -> None:
        from ._core import bounded_noun

        bounded_noun(noun)
        values, times, policies, hashes = [], [], [], []
        tail, burn = noun, False
        while isinstance(tail, Cell):
            tag, body = parts(tail.head, 2)
            if tag == 0x686B70:
                threshold, keyset = parts(body, 2)
                threshold = atom(threshold)
                keys, tree = _read_digest_set(keyset)
                if not 1 <= threshold <= len(keys) <= 32:
                    raise NockchainError("invalid signature threshold")
                policies.append(RequiredPkhPolicy(threshold, keys))
                value = fold_hashes(hash_atom(tag), hash_atom(threshold), tree_digest(tree))
            elif tag == 0x6D6974:
                relative, absolute = parts(body, 2)
                time = TimelockV1(_parse_range(relative), _parse_range(absolute))
                times.append(time)
                value = fold_hashes(
                    hash_atom(tag), _range_hash(time.relative), _range_hash(time.absolute)
                )
            elif tag == 0x786168:
                keys, tree = _read_digest_set(body)
                hashes.extend(keys)
                value = hash_cell(hash_atom(tag), tree_digest(tree))
            elif tag == 0x6E7262 and body == 0:
                burn = True
                value = hash_cell(hash_atom(tag), hash_atom(0))
            else:
                raise NockchainError("invalid lock primitive")
            values.append(value)
            tail = tail.tail
        if tail != 0 or not values:
            raise NockchainError("empty or malformed spend condition")
        root = hash_atom(0)
        for value in reversed(values):
            root = hash_cell(value, root)
        keys = policies[0].keys if policies else ()
        for policy in policies[1:]:
            keys = tuple(key for key in keys if key in policy.keys)
        threshold = policies[0].threshold if policies else 0
        for key, value in dict(
            threshold=threshold,
            keys=keys,
            timelock=times[0] if times else None,
            hashes=tuple(dict.fromkeys(hashes)),
            root=root,
            _condition=noun,
            _times=tuple(times),
            _policies=tuple(policies),
            _burn=burn,
        ).items():
            object.__setattr__(self, key, value)

    @classmethod
    def from_noun(cls, noun: Noun) -> LockV1:
        value = object.__new__(cls)
        value._initialize(noun)
        return value

    @classmethod
    def hashlock(cls, hashes) -> LockV1:
        return cls.from_noun(noun_list(Cell(0x786168, _digest_set(hashes))))

    @classmethod
    def burn(cls) -> LockV1:
        return cls.from_noun(noun_list(Cell(0x6E7262, 0)))

    def noun(self) -> Noun:
        return self._condition

    def required_pkh_policy(self) -> RequiredPkhPolicy | None:
        if not self._policies:
            return None
        if (
            any(p.threshold != self.threshold for p in self._policies)
            or len(self.keys) < self.threshold
        ):
            raise NockchainError("PKH conditions cannot share a satisfying signature map")
        return RequiredPkhPolicy(self.threshold, self.keys)

    def allows(self, height: int | None, origin: int, preimages=()) -> bool:
        from ._core import hash_each

        if self._burn:
            return False
        self.required_pkh_policy()
        if self._times and (
            height is None or any(not t.allows(height, origin) for t in self._times)
        ):
            return False
        supplied = {hash_each(value) for value in preimages}
        return all(value in supplied for value in self.hashes)

    def metadata(self) -> Noun:
        from .note_data import NoteData

        return NoteData.from_lock(self).noun()

    def _proof(self) -> Noun:
        from .lock_tree import build_lock_merkle_proof

        return build_lock_merkle_proof(self).noun()

    def _proof_hash(self) -> Digest:
        from .lock_tree import build_lock_merkle_proof

        return build_lock_merkle_proof(self).hash()


def _digest_set(values) -> Noun:
    tree = None
    keys = tuple(Digest(key) for key in values)
    if len(keys) > 32 or len(set(keys)) != len(keys):
        raise NockchainError("duplicate or excessive hash set entries")
    for key in keys:
        tree = tree_put(tree, Tree.make(key.noun(), 0, key, key, False))
    return tree_noun(tree)


def _read_digest_set(noun: Noun):
    keys = []

    def entry(key, value):
        digest = noun_digest(key)
        keys.append(digest)
        return digest, digest

    tree = read_tree(noun, False, 32, entry)
    return tuple(keys), tree


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
    return LockV1.from_noun(noun)
