"""Candidate-height fee arithmetic and exact encoded noun word counts."""

from __future__ import annotations
from dataclasses import dataclass
from ._core import (
    UINT64_MAX,
    Digest,
    Noun,
    NockchainError,
    atom,
    hash_atom,
    integer,
    leaf_count,
    noun_digest,
    parts,
)
from ._tree import metadata_entries, read_tree
from .lock_tree import LockMerkleProof

BYTHOS_PHASE = 54_000
BASE_FEE = 16_384
INPUT_FEE_DIVISOR = 4
MIN_FEE = 256


@dataclass(frozen=True, slots=True)
class FeeParameters:
    height: int = BYTHOS_PHASE
    bythos_phase: int = BYTHOS_PHASE
    base_fee: int = BASE_FEE
    input_fee_divisor: int = INPUT_FEE_DIVISOR
    min_fee: int = MIN_FEE

    def __post_init__(self):
        for value in (
            self.height,
            self.bythos_phase,
            self.base_fee,
            self.input_fee_divisor,
            self.min_fee,
        ):
            integer(value)

    @property
    def witness_divisor(self) -> int:
        return max(1, self.input_fee_divisor) if self.height >= self.bythos_phase else 1


@dataclass(frozen=True, slots=True)
class FeeBreakdown:
    seed_fee: int
    witness_fee: int
    word_fee: int
    minimum_fee: int
    witness_divisor: int


@dataclass(frozen=True, slots=True)
class WordCountBreakdown:
    seed_words: int
    witness_words: int


@dataclass(frozen=True, slots=True)
class ChainContext:
    candidate_height: int | None = None
    fees: FeeParameters = FeeParameters()

    def __post_init__(self):
        if self.candidate_height is not None:
            atom(self.candidate_height)
        if not isinstance(self.fees, FeeParameters):
            raise NockchainError("invalid fee parameters")

    @classmethod
    def at_height(cls, height: int, **rates) -> ChainContext:
        return cls(height, FeeParameters(height=height, **rates))


def compute_minimum_fee(
    seed_words: int, witness_words: int, parameters: FeeParameters = FeeParameters()
) -> FeeBreakdown:
    integer(seed_words)
    integer(witness_words)
    base = min(
        UINT64_MAX, parameters.base_fee * (1 if parameters.height >= parameters.bythos_phase else 2)
    )
    seed_fee = min(UINT64_MAX, seed_words * base)
    witness_fee = min(UINT64_MAX, witness_words * base) // parameters.witness_divisor
    words = min(UINT64_MAX, seed_fee + witness_fee)
    return FeeBreakdown(
        seed_fee, witness_fee, words, max(words, parameters.min_fee), parameters.witness_divisor
    )


def compute_bridge_fee(amount: int, nicks_fee_per_nock: int) -> int:
    integer(amount)
    integer(nicks_fee_per_nock)
    return min(UINT64_MAX, ((amount + 65_535) // 65_536) * nicks_fee_per_nock)


def _entries(noun: Noun, is_map: bool, maximum: int):
    zero = hash_atom(0)
    tree = read_tree(noun, is_map, maximum, lambda _k, _v: (zero, zero))

    def tap(node):
        if node is not None:
            yield from tap(node.right)
            yield node.key, node.value
            yield from tap(node.left)

    return tuple(tap(tree))


def note_data_words(noun: Noun) -> int:
    return 1 + sum(1 + leaf_count(value) for value in metadata_entries(noun).values())


def transaction_words(
    spends: Noun, *, merge_by_lock_root: bool = True, estimate_signatures: bool = False
) -> WordCountBreakdown:
    """Count V1 and V0-migration spends; unsigned V1 estimates include required PKHs."""
    witness_words, seed_words = 0, 0
    merged: dict[Digest, dict[int, Noun]] = {}
    for _, spend in _entries(spends, True, 64):
        version, witness, seeds, fee = parts(spend, 4)
        atom(fee)
        if version not in (0, 1):
            raise NockchainError("unsupported spend version")
        witness_words += leaf_count(witness)
        if estimate_signatures and version == 1:
            proof, signatures, _, _ = parts(witness, 4)
            condition = LockMerkleProof.from_noun(proof).condition
            condition.required_pkh_policy()
            present = len(_entries(signatures, True, 32))
            witness_words += max(0, condition.threshold - present) * 35
        for seed, _ in _entries(seeds, False, 256):
            _, root, data, amount, _ = parts(seed, 5)
            atom(amount)
            entries = metadata_entries(data)
            if merge_by_lock_root:
                merged.setdefault(noun_digest(root), {}).update(entries)
            else:
                seed_words += 1 + sum(1 + leaf_count(value) for value in entries.values())
    for entries in merged.values():
        seed_words += 1 + sum(1 + leaf_count(value) for value in entries.values())
    return WordCountBreakdown(seed_words, witness_words)
