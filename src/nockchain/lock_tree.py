"""Tagged lock trees and proofs of complete spend conditions."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TypeAlias

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
    noun_digest,
    noun_list,
    noun_tuple,
    parts,
)
from .locks import LockV1, note_first_v1

FULL = 0x6C6C7566
STUB_AXIS_HASH = Digest(
    (
        1988594973584463658,
        8158631336633700141,
        2161567007650232260,
        460329990575991155,
        8368574252173164961,
    )
)


def _tree(values, combine):
    if len(values) == 1:
        return values[0]
    middle = len(values) // 2
    return combine(_tree(values[:middle], combine), _tree(values[middle:], combine))


@dataclass(frozen=True, slots=True)
class LockTreeV1:
    """Balanced OR tree, padded to 2/4/8/16 conditions with burn leaves."""

    conditions: tuple[LockV1, ...]
    root: Digest = field(init=False)

    def __post_init__(self):
        conditions = tuple(self.conditions)
        if not 2 <= len(conditions) <= 16 or any(
            not isinstance(condition, LockV1) for condition in conditions
        ):
            raise NockchainError("a lock tree requires 2 through 16 conditions")
        arity = 1 << (len(conditions) - 1).bit_length()
        conditions += (LockV1.burn(),) * (arity - len(conditions))
        object.__setattr__(self, "conditions", conditions)
        object.__setattr__(
            self,
            "root",
            hash_cell(hash_atom(arity), _tree(tuple(c.root for c in conditions), hash_cell)),
        )

    def noun(self) -> Noun:
        return Cell(len(self.conditions), _tree(tuple(c.noun() for c in self.conditions), Cell))

    def metadata(self) -> Noun:
        from .note_data import NoteData

        return NoteData.from_lock(self).noun()


LockFormV1: TypeAlias = LockV1 | LockTreeV1


def parse_lock(noun: Noun) -> LockFormV1:
    bounded_noun(noun)
    if not isinstance(noun, Cell):
        raise NockchainError("empty or malformed lock")
    if isinstance(noun.head, Cell):
        return LockV1.from_noun(noun)
    if noun.head not in (2, 4, 8, 16):
        raise NockchainError("invalid lock arity")

    def leaves(body, count):
        if count == 1:
            return (LockV1.from_noun(body),)
        left, right = parts(body, 2)
        return leaves(left, count // 2) + leaves(right, count // 2)

    return LockTreeV1(leaves(noun.tail, noun.head))


def authorization_leaf(axis: int, path: tuple[Digest, ...]) -> bool:
    atom(axis)
    if axis == 1:
        return True
    for arity in (2, 4, 8, 16):
        if 3 * arity <= axis < 4 * arity:
            return bool(path) and path[-1] == hash_atom(arity)
    return False


@dataclass(frozen=True, slots=True)
class LockMerkleProof:
    condition: LockV1
    axis: int
    root: Digest
    path: tuple[Digest, ...] = ()
    full: bool = True

    def __post_init__(self):
        atom(self.axis)
        if not isinstance(self.condition, LockV1) or type(self.full) is not bool:
            raise NockchainError("invalid lock proof")
        object.__setattr__(self, "root", Digest(self.root))
        object.__setattr__(self, "path", tuple(Digest(d) for d in self.path))
        if len(self.path) > 63:
            raise NockchainError("lock proof path exceeds axis depth")

    def noun(self) -> Noun:
        fields = (
            self.condition.noun(),
            self.axis,
            Cell(self.root.noun(), noun_list(*(d.noun() for d in self.path))),
        )
        return noun_tuple(*((FULL, *fields) if self.full else fields))

    def hash(self) -> Digest:
        path = hash_atom(0)
        for sibling in reversed(self.path):
            path = hash_cell(sibling, path)
        proof = hash_cell(self.root, path)
        if self.full:
            return fold_hashes(hash_atom(FULL), self.condition.root, hash_atom(self.axis), proof)
        return fold_hashes(self.condition.root, STUB_AXIS_HASH, proof)

    def verify_inclusion(self) -> bool:
        axis, leaf = self.axis, self.condition.root
        if axis == 0:
            return False
        for sibling in self.path:
            if axis == 1:
                return False
            leaf = hash_cell(sibling, leaf) if axis & 1 else hash_cell(leaf, sibling)
            axis >>= 1
        return axis == 1 and leaf == self.root

    def check(self, parent_firstname: Digest) -> bool:
        return (
            note_first_v1(self.root) == Digest(parent_firstname)
            and (authorization_leaf(self.axis, self.path) if self.full else self.axis == 1)
            and self.verify_inclusion()
        )

    @classmethod
    def from_noun(cls, noun: Noun) -> LockMerkleProof:
        bounded_noun(noun)
        if not isinstance(noun, Cell):
            raise NockchainError("malformed lock proof")
        full = noun.head == FULL
        if full:
            _, condition, axis, proof = parts(noun, 4)
        else:
            condition, axis, proof = parts(noun, 3)
        root, path = parts(proof, 2)
        siblings = []
        while isinstance(path, Cell):
            siblings.append(noun_digest(path.head))
            path = path.tail
        if path != 0:
            raise NockchainError("malformed lock proof path")
        return cls(
            LockV1.from_noun(condition), atom(axis), noun_digest(root), tuple(siblings), full
        )


def build_lock_merkle_proof(
    lock: LockFormV1, leaf_number: int = 1, *, full: bool = True
) -> LockMerkleProof:
    if not isinstance(lock, (LockV1, LockTreeV1)):
        raise NockchainError("invalid lock")
    conditions = lock.conditions if isinstance(lock, LockTreeV1) else (lock,)
    if type(leaf_number) is not int or not 1 <= leaf_number <= len(conditions):
        raise NockchainError("lock leaf number out of range")
    offset = leaf_number - 1
    index = offset
    hashes = tuple(c.root for c in conditions)
    path = []
    while len(hashes) > 1:
        path.append(hashes[index ^ 1])
        hashes = tuple(hash_cell(hashes[i], hashes[i + 1]) for i in range(0, len(hashes), 2))
        index //= 2
    arity = len(conditions)
    if arity > 1:
        path.append(hash_atom(arity))
    return LockMerkleProof(
        conditions[offset], 3 * arity + offset if arity > 1 else 1, lock.root, tuple(path), full
    )


def valid_stub_axis(proof: LockMerkleProof, is_protocol_fund: bool = False) -> bool:
    return is_protocol_fund or proof.full or proof.axis == 1


def preimage_tree(values):
    from ._core import hash_each, noun_equal
    from ._tree import Tree, tree_put

    tree, seen = None, {}
    for value in values:
        bounded_noun(value)
        key = hash_each(value)
        if key in seen and not noun_equal(seen[key], value):
            raise NockchainError("conflicting hashlock preimages")
        seen[key] = value
        if len(seen) > 32:
            raise NockchainError("excessive hashlock preimages")
        item = hash_cell(key, key)
        tree = tree_put(tree, Tree.make(key.noun(), value, item, item, True))
    return tree


def parse_preimages(noun: Noun) -> tuple[Noun, ...]:
    from ._core import hash_each
    from ._tree import read_tree

    values = []

    def entry(key, value):
        digest = noun_digest(key)
        if hash_each(value) != digest:
            raise NockchainError("hashlock preimage does not match its key")
        values.append(value)
        item = hash_cell(digest, digest)
        return item, item

    read_tree(noun, True, 32, entry)
    return tuple(values)
