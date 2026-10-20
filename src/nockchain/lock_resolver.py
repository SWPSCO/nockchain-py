"""Pure lock admission and candidate-height protocol-fund policy."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from ._core import Digest, Noun, NockchainError, atom
from .locks import HeightRange, LockV1, NoteV1, TimelockV1, note_first_v1
from .lock_tree import LockFormV1, LockMerkleProof, LockTreeV1, build_lock_merkle_proof
from .note_data import LockData, NoteData
from .migration import LockV0, NoteV0

CONSENSUS_BATCH_PHASE = 170_000


@dataclass(frozen=True, slots=True)
class FundMaturity:
    candidate_height: int
    minimum: int | None

    def __post_init__(self):
        atom(self.candidate_height)
        if self.minimum is not None:
            atom(self.minimum)

    def admits(self, origin_height: int) -> bool:
        atom(origin_height)
        return self.minimum is None or (
            origin_height <= self.candidate_height
            and self.candidate_height - origin_height >= self.minimum
        )


@dataclass(frozen=True, slots=True)
class FundMaturityPolicy:
    activation_height: int
    minimum: int

    def __post_init__(self):
        atom(self.activation_height)
        atom(self.minimum)

    def fund_minimum_at(self, height: int) -> int | None:
        atom(height)
        return self.minimum if height >= self.activation_height else None

    def at(self, height: int) -> FundMaturity:
        return FundMaturity(height, self.fund_minimum_at(height))


@dataclass(frozen=True, slots=True)
class FundLockPolicy:
    """Configured recovery script and authoritative fund-note identity."""

    lock_root: Digest
    firstname: Digest
    maturity: FundMaturityPolicy

    def __post_init__(self):
        object.__setattr__(self, "lock_root", Digest(self.lock_root))
        object.__setattr__(self, "firstname", Digest(self.firstname))
        if not isinstance(self.maturity, FundMaturityPolicy):
            raise NockchainError("invalid fund maturity policy")

    def authenticates(self, proof: LockMerkleProof, firstname: Digest) -> bool:
        return (
            firstname == self.firstname
            and proof.axis == 1
            and proof.condition.root == self.lock_root
            and proof.check(note_first_v1(self.lock_root))
        )


@dataclass(frozen=True, slots=True)
class LockResolution:
    lock: LockFormV1 | LockV0
    leaf_number: int = 1
    preimages: tuple[Noun, ...] = ()
    fund_policy: FundLockPolicy | None = None

    def __post_init__(self):
        if isinstance(self.lock, LockV0):
            if self.leaf_number != 1 or self.preimages or self.fund_policy is not None:
                raise NockchainError("invalid migration unlock context")
        else:
            build_lock_merkle_proof(self.lock, self.leaf_number)
        object.__setattr__(self, "preimages", tuple(self.preimages))

    def admits(self, note: NoteV1 | NoteV0, height: int | None) -> bool:
        if isinstance(note, NoteV0):
            return (
                isinstance(self.lock, LockV0)
                and self.lock.root == note.lock.root
                and note.admits(height)
            )
        if isinstance(self.lock, LockV0):
            return False
        proof = build_lock_merkle_proof(self.lock, self.leaf_number)
        if self.fund_policy is not None:
            if (
                height is None
                or not self.fund_policy.authenticates(proof, note.name.first)
                or not self.fund_policy.maturity.at(height).admits(note.origin_page)
            ):
                return False
        elif not proof.check(note.name.first):
            return False
        return proof.condition.allows(height, note.origin_page, self.preimages)


class LockMatcher(Protocol):
    def resolve(self, note: NoteV1 | NoteV0) -> LockResolution | None: ...


def _disclosed(note: NoteV1) -> LockFormV1 | None:
    for entry in NoteData.from_noun(note.note_data).decoded():
        if entry.key == "lock" and isinstance(entry.payload, LockData):
            return entry.payload.lock
    return None


@dataclass(frozen=True, slots=True)
class SigningKeyLockMatcher:
    signer_pkh: Digest
    coinbase_relative_min: int | None = 100

    def __post_init__(self):
        object.__setattr__(self, "signer_pkh", Digest(self.signer_pkh))
        if self.coinbase_relative_min is not None:
            atom(self.coinbase_relative_min)

    def resolve(self, note: NoteV1 | NoteV0) -> LockResolution | None:
        if isinstance(note, NoteV0):
            return (
                LockResolution(note.lock)
                if note.lock.threshold == 1 and self.signer_pkh in note.lock.keys
                else None
            )
        locks = [_disclosed(note), LockV1(1, (self.signer_pkh,))]
        if self.coinbase_relative_min is not None:
            locks.append(
                LockV1(
                    1,
                    (self.signer_pkh,),
                    TimelockV1(relative=HeightRange(min=self.coinbase_relative_min)),
                )
            )
        for lock in locks:
            if lock is None or note.name.first != note_first_v1(lock.root):
                continue
            conditions = lock.conditions if isinstance(lock, LockTreeV1) else (lock,)
            for index, condition in enumerate(conditions, 1):
                if (
                    len(condition._policies) == 1
                    and len(condition._times) <= 1
                    and not condition.hashes
                    and not condition._burn
                    and condition.threshold == 1
                    and self.signer_pkh in condition.keys
                ):
                    return LockResolution(lock, index)
        return None


@dataclass(frozen=True, slots=True)
class LockRootLockMatcher:
    lock_root: Digest
    lock: LockFormV1 | None = None
    leaf_number: int = 1
    preimages: tuple[Noun, ...] = ()
    fund_policy: FundLockPolicy | None = None

    def __post_init__(self):
        object.__setattr__(self, "lock_root", Digest(self.lock_root))
        object.__setattr__(self, "preimages", tuple(self.preimages))
        if self.lock is not None and self.lock.root != self.lock_root:
            raise NockchainError("planning lock does not match its root")

    def resolve(self, note: NoteV1 | NoteV0) -> LockResolution | None:
        if isinstance(note, NoteV0):
            return None
        direct = note.name.first == note_first_v1(self.lock_root)
        fund = self.fund_policy
        if not direct and (
            fund is None or fund.lock_root != self.lock_root or note.name.first != fund.firstname
        ):
            return None
        lock = _disclosed(note) if direct else None
        if lock is None or lock.root != self.lock_root:
            lock = self.lock
        if lock is None or (not direct and isinstance(lock, LockTreeV1)):
            return None
        return LockResolution(lock, self.leaf_number, self.preimages, None if direct else fund)
