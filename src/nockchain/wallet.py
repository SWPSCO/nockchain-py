"""Deterministic single-key payment planning, change and exact fee allocation."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable

from ._core import Digest, NockchainError, PRIME, format_nocks, integer, parse_digest, parse_nocks
from .keys import ExtendedKey
from .locks import LockV1, NoteV1, note_first_v1
from .fee import ChainContext, FeeParameters
from .lock_resolver import SigningKeyLockMatcher
from .planner import PlanRequest, PlannedOutput, plan
from .transaction import (
    MAX_TRANSFER_INPUTS,
    MAX_TRANSFER_OUTPUTS,
    LockedPaymentV1,
    LockedSpendPlanV1,
    TransactionV1,
    _add,
    prepare_transaction_v1,
    minimum_transaction_fee_v1,
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
    chain: ChainContext = ChainContext()

    def __post_init__(self) -> None:
        integer(self.fee_nicks)
        if not isinstance(self.chain, ChainContext):
            raise NockchainError("invalid chain context")


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

    _transaction: TransactionV1
    _notes: tuple[NoteV1, ...]
    _summary: TransferSummary
    _public: bytes

    def summary(self) -> TransferSummary:
        return self._summary

    def notes(self) -> tuple[NoteV1, ...]:
        return self._notes

    def sign(self, key: ExtendedKey) -> TransactionV1:
        if key.public_bytes() != self._public or not self._notes:
            raise NockchainError("signing key does not match prepared transfer")
        return self._transaction.sign(key)


def minimum_transfer_fee_v1(
    inputs: int, recipients: Iterable[Digest], fees: FeeParameters = FeeParameters()
) -> int:
    recipients = tuple(Digest(recipient) for recipient in recipients)
    if (
        type(inputs) is not int
        or not 1 <= inputs <= MAX_TRANSFER_INPUTS
        or not 1 <= len(recipients) <= MAX_TRANSFER_OUTPUTS
    ):
        raise NockchainError("transfer size out of range")
    locks = tuple(LockV1(1, (recipient,)) for recipient in dict.fromkeys(recipients))
    return minimum_transaction_fee_v1((locks[0],) * inputs, locks, fees)


def sign_transfer_v1(key: ExtendedKey, plans: Iterable[SpendPlanV1]) -> TransactionV1:
    lock = LockV1(1, (parse_digest(key.address()),))
    prepared = []
    for spend in plans:
        if spend.lock_root != lock.root:
            raise NockchainError("input lock does not authorize this key")
        outputs = tuple(
            LockedPaymentV1(LockV1(1, (output.recipient,)), output.nicks)
            for output in spend.outputs
        )
        prepared.append(LockedSpendPlanV1(spend.note, lock, outputs, spend.fee))
    return prepare_transaction_v1(prepared).sign(key)


def _transfer(sender, notes, payments, options, manual):
    notes, payments = tuple(notes), tuple(payments)
    if not notes or not 1 <= len(payments) <= MAX_TRANSFER_OUTPUTS:
        raise NockchainError("transfer size out of range")
    address = sender.address()
    pkh = parse_digest(address)
    change = options.change_address or address
    refund = PlannedOutput.payment(parse_digest(change), 0)
    candidates = []
    for unspent in notes:
        if not isinstance(unspent, UnspentNote):
            raise NockchainError("invalid input record")
        if unspent.note.name.first != note_first_v1(unspent.lock_root):
            raise NockchainError("input name does not bind supplied lock root")
        candidates.append(unspent.note)
    outputs, review_payments, payment_total = [], [], 0
    for payment in payments:
        amount = parse_nocks(payment.amount)
        if not 0 < amount < PRIME:
            raise NockchainError("invalid payment amount")
        outputs.append(PlannedOutput.payment(parse_digest(payment.address), amount))
        payment_total = _add(payment_total, amount)
        review_payments.append(Payment(payment.address, format_nocks(amount)))
    result = plan(
        PlanRequest(
            tuple(candidates),
            tuple(outputs),
            refund,
            options.chain,
            tuple(note.name for note in candidates) if manual else None,
            fee_nicks=options.fee_nicks or None,
        ),
        SigningKeyLockMatcher(pkh),
    )
    if result.final_fee < result.minimum_fee:
        raise NockchainError("fee below minimum")
    summary = TransferSummary(
        len(result.selected),
        result.selected_total,
        payment_total,
        result.final_fee,
        sum(amount for _, amount in result.refunds),
        change,
        tuple(review_payments),
    )
    return PreparedTransfer(result.transaction, result.selected, summary, sender.public_bytes())


def prepare_transfer(
    sender: ExtendedKey,
    notes: Iterable[UnspentNote],
    payments: Iterable[Payment],
    options: TransferOptions = TransferOptions(),
) -> PreparedTransfer:
    """Consume the supplied notes using the same planner as automatic selection."""
    return _transfer(sender, notes, payments, options, True)


def select_transfer(
    sender: ExtendedKey,
    notes: Iterable[UnspentNote],
    payments: Iterable[Payment],
    options: TransferOptions = TransferOptions(),
) -> PreparedTransfer:
    """Select sufficient notes by amount, then Base58 name, with exact fee solving."""
    return _transfer(sender, notes, payments, options, False)
