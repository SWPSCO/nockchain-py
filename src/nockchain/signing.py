"""Validate and sign data-only bundles prepared by the Nockblocks V1 API."""

import base64
import copy
import re
from dataclasses import dataclass
from typing import Any

from ._core import NockchainError, parse_digest, cue, jam, noun_equal
from .fee import FeeParameters, ChainContext
from .keys import ExtendedKey
from .locks import LockV1, NoteName, NoteV1
from .transaction import TransactionV1, parse_transaction_v1
from .planner import PlannedOutput, PlanRequest, plan
from .lock_resolver import SigningKeyLockMatcher


def _check(condition, message):
    if not condition:
        raise NockchainError(message)


def _object(value, fields):
    _check(isinstance(value, dict), "expected an object")
    _check(value.keys() <= set(fields.split()), "unexpected bundle field")
    return value


def _integer(value):
    _check(
        isinstance(value, str) and re.fullmatch(r"(0|[1-9][0-9]{0,19})", value),
        "expected an unsigned decimal integer",
    )
    result = int(value)
    _check(result < 1 << 64, "integer exceeds u64")
    return result


def _address(value):
    _check(isinstance(value, str) and 0 < len(value) <= 60, "invalid digest")
    _check(str(parse_digest(value)) == value, "noncanonical digest")
    return value


def _array(value):
    _check(isinstance(value, list) and 0 < len(value) <= 64, "array count out of range")
    return value


def _bytes(value, maximum):
    _check(
        isinstance(value, str) and len(value) <= (maximum + 2) // 3 * 4, "encoded data is too large"
    )
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise NockchainError("invalid base64") from None
    _check(
        0 < len(result) <= maximum and base64.b64encode(result).decode() == value,
        "expected bounded canonical base64",
    )
    return result


def _data(value):
    encoded = _bytes(value, 65536)
    noun = cue(encoded)
    _check(jam(noun) == encoded, "noncanonical note-data JAM")
    return noun


@dataclass(frozen=True)
class InspectedSigningBundle:
    bundle: dict[str, Any]
    transaction: TransactionV1
    review: dict[str, Any]


def inspect_signing_bundle(value: Any) -> InspectedSigningBundle:
    """Check intent, commitments and signatures; indexed context is not a chain proof."""
    value = _object(
        value,
        "format version network tip candidateHeight sourceAddress payments rawTransaction inputs",
    )
    _check(
        value.get("format") == "nockchain-signing-bundle"
        and type(value.get("version")) is int
        and value["version"] == 1,
        "unsupported signing bundle",
    )
    network = value.get("network")
    _check(
        isinstance(network, str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", network),
        "invalid network",
    )
    tip = _object(value.get("tip"), "blockId height")
    tip_height, height = _integer(tip.get("height")), _integer(value.get("candidateHeight"))
    _address(tip.get("blockId"))
    _check(height == tip_height + 1, "candidate height must follow the indexed tip")
    source = _address(value.get("sourceAddress"))
    source_hash = parse_digest(source)
    payments = []
    for item in _array(value.get("payments")):
        item = _object(item, "address amountNicks")
        amount = _integer(item.get("amountNicks"))
        _check(amount > 0, "payment must be positive")
        payments.append({"address": _address(item.get("address")), "amountNicks": str(amount)})
    notes = []
    for item in _array(value.get("inputs")):
        item = _object(item, "name originPage amountNicks noteData")
        name = _object(item.get("name"), "firstName lastName")
        notes.append(
            NoteV1(
                _integer(item.get("originPage")),
                NoteName(
                    parse_digest(_address(name.get("firstName"))),
                    parse_digest(_address(name.get("lastName"))),
                ),
                _data(item.get("noteData")),
                _integer(item.get("amountNicks")),
            )
        )
    encoded = _bytes(value.get("rawTransaction"), 262144)
    transaction = parse_transaction_v1(encoded, fees=FeeParameters(height=height))
    _check(transaction.jam() == encoded, "noncanonical transaction JAM")
    transaction.validate_inputs(notes, height)
    transaction.verify_signatures(require_threshold=False)
    summary = transaction.summary()
    planned = plan(
        PlanRequest(
            tuple(notes),
            tuple(
                PlannedOutput.payment(parse_digest(p["address"]), int(p["amountNicks"]))
                for p in payments
            ),
            PlannedOutput.payment(source_hash, 0),
            ChainContext.at_height(height),
            selection=tuple(note.name for note in notes),
        ),
        SigningKeyLockMatcher(source_hash),
    )
    _check(summary.fee_nicks == planned.final_fee, "bundle fee differs from the local plan")
    planned_spends = {s.name: s.signature_hash for s in planned.transaction.summary().spends}
    for spend in summary.spends:
        _check(
            planned_spends.get(spend.name) == spend.signature_hash,
            "transaction differs from the local payment plan",
        )
    expected = {}
    for payment in payments + [{"address": source, "amountNicks": "0"}]:
        lock = LockV1(1, (parse_digest(payment["address"]),))
        address, amount, _ = expected.get(lock.root, (payment["address"], 0, lock))
        amount += int(payment["amountNicks"])
        _check(amount < 1 << 64, "payment total overflow")
        expected[lock.root] = (address, amount, lock)
    actual = {}
    for spend in summary.spends:
        _check(
            spend.proof is not None
            and isinstance(spend.lock, LockV1)
            and spend.lock.threshold == 1
            and source_hash in spend.lock.keys
            and len(spend.outputs) > 0,
            "input is not controlled by the source address",
        )
        for output in spend.outputs:
            target = expected.get(output.lock_root)
            _check(
                target is not None and noun_equal(output.note_data, target[2].metadata()),
                "undeclared output or unexpected output metadata",
            )
            actual[output.lock_root] = actual.get(output.lock_root, 0) + output.nicks
    change = 0
    for root, (address, expected_amount, _) in expected.items():
        amount = actual.get(root, 0)
        if address == source:
            _check(amount >= expected_amount, "source payment amount mismatch")
            change = amount - expected_amount
        else:
            _check(amount == expected_amount, "payment amount mismatch")
    bundle = copy.deepcopy(
        {
            "format": value["format"],
            "version": value["version"],
            "network": network,
            "tip": {"blockId": tip["blockId"], "height": tip["height"]},
            "candidateHeight": value["candidateHeight"],
            "sourceAddress": source,
            "payments": payments,
            "rawTransaction": value["rawTransaction"],
            "inputs": value["inputs"],
        }
    )
    review = {
        "transactionId": str(summary.id),
        "network": network,
        "tip": bundle["tip"],
        "candidateHeight": bundle["candidateHeight"],
        "sourceAddress": source,
        "payments": payments,
        "changeNicks": str(change),
        "feeNicks": str(summary.fee_nicks),
        "minimumFeeNicks": str(summary.minimum_fee_nicks),
        "inputCount": len(notes),
        "fullySigned": all(len(s.signed_keys) == s.lock.threshold for s in summary.spends),
    }
    return InspectedSigningBundle(bundle, transaction, review)


def sign_signing_bundle(value: Any, key: ExtendedKey) -> dict[str, Any]:
    """Revalidate, sign with the source key, and return a fully signed bundle."""
    inspected = inspect_signing_bundle(value)
    _check(
        key.is_private and key.address() == inspected.bundle["sourceAddress"],
        "signing key does not match source address",
    )
    signed = inspected.transaction.sign(key)
    signed.verify_signatures()
    result = {**inspected.bundle, "rawTransaction": base64.b64encode(signed.jam()).decode()}
    inspect_signing_bundle(result)
    return result
