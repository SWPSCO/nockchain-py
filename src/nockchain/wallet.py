"""Deterministic single-key payment planning, change and exact fee allocation."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable

from ._core import Digest, NockchainError, PRIME, format_nocks, integer, parse_digest, parse_nocks
from ._tree import digest_order
from .keys import ExtendedKey, lock_root
from .locks import LockV1, NoteV1, note_first_v1
from .transaction import (
    MAX_TRANSFER_INPUTS,
    MAX_TRANSFER_OUTPUTS,
    LockedPaymentV1,
    LockedSpendPlanV1,
    TransactionV1,
    _add,
    prepare_transaction_v1,
)


@dataclass(frozen=True, slots=True)
class UnspentNote:
    note: NoteV1
    lock_root: Digest

    def __post_init__(self) -> None:
        object.__setattr__(self, "lock_root", Digest(self.lock_root))
        if not isinstance(self.note, NoteV1):
            raise NockchainError("invalid note record")


@dataclass(frozen=True, slots=True)
class Payment:
    address: str
    amount: str


@dataclass(frozen=True, slots=True)
class PaymentV1:
    recipient: Digest
    nicks: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "recipient", Digest(self.recipient))
        integer(self.nicks, PRIME - 1, "payment")
        if self.nicks == 0:
            raise NockchainError("zero payment")


@dataclass(frozen=True, slots=True)
class SpendPlanV1:
    note: NoteV1
    lock_root: Digest
    outputs: tuple[PaymentV1, ...]
    fee: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", tuple(self.outputs))
        object.__setattr__(self, "lock_root", Digest(self.lock_root))
        integer(self.fee, PRIME - 1, "fee")


@dataclass(frozen=True, slots=True)
class TransferOptions:
    change_address: str = ""
    fee_nicks: int = 0

    def __post_init__(self) -> None:
        integer(self.fee_nicks)


@dataclass(frozen=True, slots=True)
class TransferSummary:
    input_count: int
    input_nicks: int
    payment_nicks: int
    fee_nicks: int
    change_nicks: int
    change_address: str
    payments: tuple[Payment, ...]


@dataclass(frozen=True, slots=True)
class PreparedTransfer:
    """A reviewable immutable plan. Signing must use the reviewed sender."""

    _plans: tuple[SpendPlanV1, ...]
    _summary: TransferSummary
    _public: bytes

    def summary(self) -> TransferSummary:
        return self._summary

    def notes(self) -> tuple[NoteV1, ...]:
        return tuple(plan.note for plan in self._plans)

    def sign(self, key: ExtendedKey) -> TransactionV1:
        if key.public_bytes() != self._public or not self._plans:
            raise NockchainError("signing key does not match prepared transfer")
        return sign_transfer_v1(key, self._plans)


def minimum_transfer_fee_v1(inputs: int, recipients: Iterable[Digest]) -> int:
    recipients = tuple(Digest(recipient) for recipient in recipients)
    if (
        type(inputs) is not int
        or not 1 <= inputs <= MAX_TRANSFER_INPUTS
        or not 1 <= len(recipients) <= MAX_TRANSFER_OUTPUTS
    ):
        raise NockchainError("transfer size out of range")
    return len(set(recipients)) * 13 * (1 << 14) + inputs * 56 * (1 << 12)


def sign_transfer_v1(key: ExtendedKey, plans: Iterable[SpendPlanV1]) -> TransactionV1:
    lock = LockV1(1, (parse_digest(key.address()),))
    prepared = []
    for plan in plans:
        if plan.lock_root != lock.root:
            raise NockchainError("input lock does not authorize this key")
        outputs = tuple(
            LockedPaymentV1(LockV1(1, (output.recipient,)), output.nicks) for output in plan.outputs
        )
        prepared.append(LockedSpendPlanV1(plan.note, lock, outputs, plan.fee))
    return prepare_transaction_v1(prepared).sign(key)


def prepare_transfer(
    sender: ExtendedKey,
    notes: Iterable[UnspentNote],
    payments: Iterable[Payment],
    options: TransferOptions = TransferOptions(),
) -> PreparedTransfer:
    """Consume every supplied note, merging recipients and making change explicit."""
    notes, payments = tuple(notes), tuple(payments)
    if not 1 <= len(notes) <= MAX_TRANSFER_INPUTS or not 1 <= len(payments) <= MAX_TRANSFER_OUTPUTS:
        raise NockchainError("transfer size out of range")
    address = sender.address()
    root = lock_root(parse_digest(address))
    bound = note_first_v1(root)
    change = options.change_address or address
    change_pkh = parse_digest(change)
    input_total, payment_total, seen = 0, 0, set()
    for unspent in notes:
        note = unspent.note
        note.hash()
        if note.name in seen or note.name.first != bound or unspent.lock_root != root:
            raise NockchainError("duplicate or unauthorized input")
        seen.add(note.name)
        input_total = _add(input_total, note.nicks)
    recipients, amounts, positions, review_payments = [], [], {}, []
    for payment in payments:
        recipient = parse_digest(payment.address)
        amount = parse_nocks(payment.amount)
        if not 0 < amount < PRIME:
            raise NockchainError("invalid payment amount")
        payment_total = _add(payment_total, amount)
        if recipient in positions:
            index = positions[recipient]
            amounts[index] = _add(amounts[index], amount)
        else:
            positions[recipient] = len(recipients)
            recipients.append(recipient)
            amounts.append(amount)
        review_payments.append(Payment(payment.address, format_nocks(amount)))
    if payment_total >= input_total:
        raise NockchainError("insufficient funds for payment and fees")
    available = input_total - payment_total
    minimum = minimum_transfer_fee_v1(len(notes), recipients)
    fee = options.fee_nicks
    if fee == 0:
        fee = minimum
        if available > fee:
            with_change = recipients if change_pkh in positions else [*recipients, change_pkh]
            fee = minimum_transfer_fee_v1(len(notes), with_change)
            if fee > available >= minimum:
                fee = available
    if fee > available:
        raise NockchainError("insufficient funds for payment and fees")
    change_nicks = available - fee
    if change_nicks:
        if change_pkh in positions:
            index = positions[change_pkh]
            amounts[index] = _add(amounts[index], change_nicks)
        else:
            recipients.append(change_pkh)
            amounts.append(change_nicks)
    if fee < minimum_transfer_fee_v1(len(notes), recipients):
        raise NockchainError("fee below minimum")
    plans, remaining_fee, output, output_count = [], fee, 0, 0
    for unspent in notes:
        input_fee = min(remaining_fee, unspent.note.nicks - 1)
        remaining_fee -= input_fee
        remaining = unspent.note.nicks - input_fee
        plan_outputs = []
        while remaining:
            if output >= len(amounts):
                raise NockchainError("input values cannot be allocated to the outputs")
            value = min(remaining, amounts[output])
            plan_outputs.append(PaymentV1(recipients[output], value))
            output_count += 1
            if output_count > MAX_TRANSFER_OUTPUTS:
                raise NockchainError("output count out of range")
            remaining -= value
            amounts[output] -= value
            if amounts[output] == 0:
                output += 1
        plans.append(SpendPlanV1(unspent.note, unspent.lock_root, tuple(plan_outputs), input_fee))
    if remaining_fee:
        raise NockchainError("notes cannot cover the requested fee")
    summary = TransferSummary(
        len(notes), input_total, payment_total, fee, change_nicks, change, tuple(review_payments)
    )
    return PreparedTransfer(tuple(plans), summary, sender.public_bytes())


def select_transfer(
    sender: ExtendedKey,
    notes: Iterable[UnspentNote],
    payments: Iterable[Payment],
    options: TransferOptions = TransferOptions(),
) -> PreparedTransfer:
    """Choose sufficient notes largest-first with deterministic note-name ties."""
    root = lock_root(parse_digest(sender.address()))
    bound = note_first_v1(root)
    candidates, seen = [], set()
    for unspent in notes:
        note = unspent.note
        note.hash()
        if note.name in seen:
            raise NockchainError("duplicate input note")
        seen.add(note.name)
        if unspent.lock_root == root and note.name.first == bound:
            candidates.append(unspent)
    candidates.sort(
        key=lambda unspent: (
            -unspent.note.nicks,
            digest_order(unspent.note.name.first),
            digest_order(unspent.note.name.last),
        )
    )
    payments = tuple(payments)
    failure = NockchainError("no spendable notes")
    for count in range(1, min(len(candidates), MAX_TRANSFER_INPUTS) + 1):
        try:
            return prepare_transfer(sender, candidates[:count], payments, options)
        except NockchainError as error:
            failure = error
    raise failure
