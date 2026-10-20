"""Pure deterministic note selection, fee solving, and per-input conservation."""

from __future__ import annotations
from dataclasses import dataclass, replace
from ._core import Digest, Noun, NockchainError, atom, noun_equal, parts
from .fee import ChainContext, WordCountBreakdown, transaction_words
from .locks import LockV1, NoteName, NoteV1
from .lock_resolver import LockMatcher, LockResolution
from .note_data import NoteData
from .migration import NoteV0, LockV0
from .transaction import (
    MAX_TRANSFER_INPUTS,
    LockedPaymentV1,
    LockedSpendPlanV1,
    TransactionV1,
    _add,
    _prepare_transaction,
)


@dataclass(frozen=True, slots=True)
class PlannedOutput:
    lock_root: Digest
    note_data: Noun
    amount: int

    def __post_init__(self):
        object.__setattr__(self, "lock_root", Digest(self.lock_root))
        object.__setattr__(self, "note_data", NoteData.from_noun(self.note_data).noun())
        atom(self.amount)

    @classmethod
    def payment(cls, pkh: Digest, amount: int, *, private: bool = False) -> PlannedOutput:
        lock = LockV1(1, (pkh,))
        return cls(lock.root, 0 if private else lock.metadata(), amount)


@dataclass(frozen=True, slots=True)
class PlanRequest:
    candidates: tuple[NoteV1 | NoteV0, ...]
    outputs: tuple[PlannedOutput, ...]
    refund: PlannedOutput
    chain: ChainContext = ChainContext()
    selection: tuple[NoteName, ...] | None = None
    order: str = "descending"
    fee_nicks: int | None = None
    sweep: PlannedOutput | None = None
    version: int = 1

    def __post_init__(self):
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "outputs", tuple(self.outputs))
        if self.selection is not None:
            object.__setattr__(self, "selection", tuple(self.selection))
        if type(self.version) is not int or self.version not in (0, 1):
            raise NockchainError("invalid candidate version")
        if self.order not in ("ascending", "descending"):
            raise NockchainError("invalid selection order")
        if self.fee_nicks is not None:
            atom(self.fee_nicks)
        if not isinstance(self.chain, ChainContext) or not isinstance(self.refund, PlannedOutput):
            raise NockchainError("invalid planning context")
        if any(not isinstance(output, PlannedOutput) for output in self.outputs):
            raise NockchainError("invalid planned output")
        if self.sweep is not None and not isinstance(self.sweep, PlannedOutput):
            raise NockchainError("invalid sweep output")


@dataclass(frozen=True, slots=True)
class PlanResult:
    transaction: TransactionV1
    selected: tuple[NoteV1 | NoteV0, ...]
    selected_total: int
    outputs: tuple[PlannedOutput, ...]
    refunds: tuple[tuple[NoteName, int], ...]
    final_fee: int
    minimum_fee: int
    word_counts: WordCountBreakdown


def _merge(outputs: list[PlannedOutput], output: PlannedOutput) -> None:
    if output.amount == 0:
        return
    for index, old in enumerate(outputs):
        if old.lock_root == output.lock_root:
            if not noun_equal(old.note_data, output.note_data):
                raise NockchainError("conflicting note data for the same output lock")
            outputs[index] = replace(old, amount=atom(_add(old.amount, output.amount)))
            return
    outputs.append(output)


def _candidates(request: PlanRequest, matcher: LockMatcher):
    seen = set()
    for note in request.candidates:
        if not isinstance(note, (NoteV1, NoteV0)):
            raise NockchainError("invalid input note")
        note.hash()
        if note.name in seen:
            raise NockchainError("duplicate input note")
        seen.add(note.name)
    if request.selection is not None:
        if len(set(request.selection)) != len(request.selection):
            raise NockchainError("duplicate manual input")
        if any(name not in seen for name in request.selection):
            raise NockchainError("manual input is missing from snapshot")
    result = []
    for note in request.candidates:
        if request.selection is not None and note.name not in request.selection:
            continue
        resolution = (
            matcher.resolve(note) if isinstance(note, NoteV0) == (request.version == 0) else None
        )
        if (
            resolution is not None
            and resolution.admits(note, request.chain.candidate_height)
            and (
                request.chain.fees.height >= request.chain.fees.bythos_phase
                or isinstance(resolution.lock, (LockV1, LockV0))
            )
        ):
            result.append((note, resolution))
        elif request.selection is not None:
            raise NockchainError("manual input is not spendable")
    result.sort(
        key=lambda row: (
            -row[0].nicks if request.order == "descending" else row[0].nicks,
            str(row[0].name.first),
            str(row[0].name.last),
        )
    )
    return result


def _assemble(selected: list[tuple[NoteV1, LockResolution]], outputs, refund, fee, chain):
    if not 1 <= len(selected) <= MAX_TRANSFER_INPUTS:
        raise NockchainError("input count out of range")
    total, payment_total = 0, 0
    for note, _ in selected:
        total = _add(total, note.nicks)
    for output in outputs:
        payment_total = _add(payment_total, output.amount)
    if _add(payment_total, fee) > total:
        raise NockchainError("insufficient funds")
    if fee > total - len(selected):
        raise NockchainError("fee leaves an input without a positive seed")
    remaining = [output.amount for output in outputs]
    remaining_fee, plans, emitted, refunds = fee, [], [], []
    fund_policy = None
    for note, resolved in selected:
        input_fee = min(remaining_fee, note.nicks - 1)
        remaining_fee -= input_fee
        capacity, allocated = note.nicks - input_fee, []
        for index, output in enumerate(outputs):
            amount = min(capacity, remaining[index])
            if amount:
                _merge(allocated, replace(output, amount=amount))
                capacity -= amount
                remaining[index] -= amount
        if capacity:
            refunds.append((note.name, capacity))
            _merge(allocated, replace(refund, amount=capacity))
        plans.append(
            LockedSpendPlanV1(
                note,
                resolved.lock,
                tuple(LockedPaymentV1(o.lock_root, o.amount, o.note_data) for o in allocated),
                input_fee,
                resolved.leaf_number,
                resolved.preimages,
            )
        )
        if resolved.fund_policy is not None:
            if fund_policy is not None and fund_policy != resolved.fund_policy:
                raise NockchainError("conflicting fund policies")
            fund_policy = resolved.fund_policy
        for output in allocated:
            _merge(emitted, output)
    if remaining_fee or any(remaining):
        raise NockchainError("input allocation does not cover payments and fee")
    transaction = _prepare_transaction(plans, chain.fees, fund_policy, False)
    words = transaction_words(
        parts(transaction.noun(), 3)[2],
        merge_by_lock_root=chain.fees.height >= chain.fees.bythos_phase,
        estimate_signatures=True,
    )
    migration_words = sum(
        note.lock.threshold * 30 for note, _ in selected if isinstance(note, NoteV0)
    )
    if migration_words:
        words = WordCountBreakdown(words.seed_words, words.witness_words + migration_words)
    return PlanResult(
        transaction,
        tuple(note for note, _ in selected),
        total,
        tuple(emitted),
        tuple(refunds),
        fee,
        transaction.summary().minimum_fee_nicks,
        words,
    )


def plan(request: PlanRequest, matcher: LockMatcher) -> PlanResult:
    candidates = _candidates(request, matcher)
    if not candidates:
        raise NockchainError("no spendable inputs")
    outputs = []
    for output in request.outputs:
        if output.amount == 0:
            raise NockchainError("payment amount must be positive")
        _merge(outputs, output)
    if request.sweep is not None and outputs:
        raise NockchainError("sweep has one planner-assigned destination")
    if request.sweep is None and not outputs:
        raise NockchainError("at least one payment is required")
    payment_total = 0
    for output in outputs:
        payment_total = _add(payment_total, output.amount)
    all_inputs = request.sweep is not None or request.selection is not None
    fee = request.fee_nicks if request.fee_nicks is not None else request.chain.fees.min_fee
    for _ in range(len(candidates) * 2 + 8):
        needed, total, selected = _add(payment_total, fee), 0, []
        for candidate in candidates:
            total = _add(total, candidate[0].nicks)
            selected.append(candidate)
            if not all_inputs and total >= needed:
                break
        round_outputs = list(outputs)
        if request.sweep is not None:
            if total <= fee:
                raise NockchainError("balance does not cover the network fee")
            round_outputs.append(replace(request.sweep, amount=total - fee))
        result = _assemble(selected, round_outputs, request.refund, fee, request.chain)
        if request.fee_nicks is not None or result.minimum_fee <= fee:
            return result
        if request.sweep is None:
            remainder = total - payment_total
            if request.chain.fees.min_fee <= remainder <= result.minimum_fee:
                try:
                    exact = _assemble(
                        selected, round_outputs, request.refund, remainder, request.chain
                    )
                    if exact.minimum_fee <= remainder:
                        return exact
                except NockchainError:
                    pass
        fee = result.minimum_fee
    raise NockchainError("network fee does not converge")
