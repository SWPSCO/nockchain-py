"""Canonical bounded noun treaps; internal persistent nodes preserve snapshots."""

from __future__ import annotations
from dataclasses import dataclass, replace
from typing import Callable

from ._core import (
    Cell,
    Digest,
    Noun,
    NockchainError,
    atom,
    bounded_noun,
    hash_atom,
    hash_cell,
    hash_each,
    hash_noun,
    noun_equal,
    noun_tuple,
    parts,
)


def digest_order(digest: Digest) -> tuple[int, ...]:
    return tuple(reversed(digest))


def noun_less(a: Noun, b: Noun) -> bool:
    if noun_equal(a, b):
        return True
    if not isinstance(a, Cell) or not isinstance(b, Cell):
        return not isinstance(a, Cell) and not isinstance(b, Cell) and a < b
    return noun_less(a.tail, b.tail) if noun_equal(a.head, b.head) else noun_less(a.head, b.head)


@dataclass(frozen=True, slots=True)
class Tree:
    key: Noun
    value: Noun
    regular: Digest
    signature: Digest
    sort: Digest
    priority: Digest
    is_map: bool
    left: Tree | None = None
    right: Tree | None = None

    @classmethod
    def make(cls, key: Noun, value: Noun, regular: Digest, signature: Digest, is_map: bool) -> Tree:
        sort = hash_noun(key)
        return cls(key, value, regular, signature, sort, hash_cell(sort, sort), is_map)


def tree_noun(tree: Tree | None) -> Noun:
    if tree is None:
        return 0
    value = Cell(tree.key, tree.value) if tree.is_map else tree.key
    return noun_tuple(value, tree_noun(tree.left), tree_noun(tree.right))


def tree_digest(tree: Tree | None, signature: bool = False) -> Digest:
    if tree is None:
        return hash_atom(0)
    value = tree.signature if signature else tree.regular
    return hash_cell(
        value, hash_cell(tree_digest(tree.left, signature), tree_digest(tree.right, signature))
    )


def _less(a: Tree, b: Tree, priority: bool = False) -> bool:
    x, y = (a.priority, b.priority) if priority else (a.sort, b.sort)
    return noun_less(a.key, b.key) if x == y else digest_order(x) < digest_order(y)


def tree_put(tree: Tree | None, node: Tree) -> Tree:
    if tree is None:
        return node
    if noun_equal(tree.key, node.key):
        return replace(node, left=tree.left, right=tree.right)
    if _less(node, tree):
        child = tree_put(tree.left, node)
        if not _less(tree, child, True):
            return replace(child, right=replace(tree, left=child.right))
        return replace(tree, left=child)
    child = tree_put(tree.right, node)
    if not _less(tree, child, True):
        return replace(child, left=replace(tree, right=child.left))
    return replace(tree, right=child)


def read_tree(
    noun: Noun, is_map: bool, maximum: int, entry: Callable[[Noun, Noun], tuple[Digest, Digest]]
) -> Tree | None:
    bounded_noun(noun)
    tree = None
    stack, count = [noun], 0
    while stack:
        value = stack.pop()
        if value == 0:
            continue
        key, left, right = parts(value, 3)
        count += 1
        if count > maximum:
            raise NockchainError("tree entry limit exceeded")
        val = 0
        if is_map:
            key, val = parts(key, 2)
        regular, signature = entry(key, val)
        tree = tree_put(tree, Tree.make(key, val, regular, signature, is_map))
        stack.extend((left, right))
    if not noun_equal(noun, tree_noun(tree)):
        raise NockchainError("noncanonical or duplicate tree entries")
    return tree


def metadata_entries(noun: Noun) -> dict[int, Noun]:
    entries = {}

    def entry(key: Noun, value: Noun) -> tuple[Digest, Digest]:
        tag = atom(key)
        entries[tag] = value
        digest = hash_cell(hash_atom(tag), hash_each(value))
        return digest, digest

    read_tree(noun, True, 64, entry)
    return entries


def metadata_hash(noun: Noun) -> Digest:
    def entry(key: Noun, value: Noun) -> tuple[Digest, Digest]:
        digest = hash_cell(hash_atom(atom(key)), hash_each(value))
        return digest, digest

    return tree_digest(read_tree(noun, True, 64, entry))
