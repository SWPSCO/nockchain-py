"""Immutable V1 preparation, inspection, partial signing, and validation."""

from __future__ import annotations
from dataclasses import dataclass, replace
from typing import Iterable

from ._core import (
    Cell,
    Digest,
    Noun,
    NockchainError,
    UINT64_MAX,
    atom,
    bounded_noun,
    cue,
    fold_hashes,
    hash_atom,
    hash_cell,
    hash_each,
    hash_noun,
    integer,
    jam,
    leaf_count,
    noun_digest,
    noun_equal,
    noun_tuple,
    parts,
)
from ._curve import parse_point
from ._tree import (
    Tree,
    metadata_entries,
    metadata_hash,
    read_tree,
    tree_digest,
    tree_noun,
    tree_put,
)
from .keys import ExtendedKey, Signature, public_key_hash, public_noun, verify_digest
from .locks import LockV1, NoteName, NoteV1
from .lock_tree import (
    LockFormV1,
    LockTreeV1,
    LockMerkleProof,
    build_lock_merkle_proof,
    parse_lock,
    preimage_tree,
    parse_preimages,
)
from .lock_resolver import FundLockPolicy
from .fee import FeeParameters, compute_minimum_fee
from .migration import NoteV0, LockV0, note_first_v0

MAX_TRANSFER_INPUTS = 64
MAX_TRANSFER_OUTPUTS = 256
MAX_NOTE_DATA_WORDS_V1 = 2048


def _add(a: int, b: int) -> int:
    return integer(a + b, UINT64_MAX, "amount total")


@dataclass(frozen=True, slots=True)
class LockedPaymentV1:
    lock: LockFormV1 | Digest
    nicks: int
    note_data: Noun | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.lock, (LockV1, LockTreeV1, Digest)) or atom(self.nicks) == 0:
            raise NockchainError("invalid output")
        if self.note_data is not None:
            metadata_hash(self.note_data)

    @property
    def lock_root(self) -> Digest:
        return self.lock if isinstance(self.lock, Digest) else self.lock.root

    def metadata(self) -> Noun:
        if self.note_data is not None:
            return self.note_data
        return 0 if isinstance(self.lock, Digest) else self.lock.metadata()


@dataclass(frozen=True, slots=True)
class LockedSpendPlanV1:
    note: NoteV1 | NoteV0
    lock: LockFormV1 | LockV0
    outputs: tuple[LockedPaymentV1, ...]
    fee: int
    leaf_number: int = 1
    preimages: tuple[Noun, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", tuple(self.outputs))
        object.__setattr__(self, "preimages", tuple(self.preimages))
        atom(self.fee)
        if not isinstance(self.note, (NoteV1, NoteV0)) or not isinstance(
            self.lock, (LockV1, LockTreeV1, LockV0)
        ):
            raise NockchainError("invalid input plan")
        if isinstance(self.lock, LockV0) != isinstance(self.note, NoteV0):
            raise NockchainError("input and lock version differ")
        if not isinstance(self.lock, LockV0):
            build_lock_merkle_proof(self.lock, self.leaf_number)
        if any(not isinstance(output, LockedPaymentV1) for output in self.outputs):
            raise NockchainError("invalid output plan")


@dataclass(frozen=True, slots=True)
class OutputV1:
    lock_root: Digest
    note_data: Noun
    nicks: int
    parent_hash: Digest

    def lock(self) -> LockFormV1:
        """Return the output policy only if its metadata authenticates the root."""
        entries = metadata_entries(self.note_data)
        if 0x6B636F6C not in entries:
            raise NockchainError("output lock metadata is absent")
        tag, condition = parts(entries[0x6B636F6C], 2)
        if tag != 0:
            raise NockchainError("unsupported output lock metadata")
        lock = parse_lock(condition)
        if lock.root != self.lock_root:
            raise NockchainError("output metadata does not authenticate its lock")
        return lock


@dataclass(frozen=True, slots=True)
class SpendSummaryV1:
    name: NoteName
    lock: LockV1 | LockV0
    fee: int
    outputs: tuple[OutputV1, ...]
    signed_keys: tuple[Digest, ...]
    signature_hash: Digest
    proof: LockMerkleProof | None


@dataclass(frozen=True, slots=True)
class TransactionSummaryV1:
    id: Digest
    fee_nicks: int
    output_nicks: int
    minimum_fee_nicks: int
    spends: tuple[SpendSummaryV1, ...]


@dataclass(frozen=True, slots=True)
class _SignedPKH:
    pkh: Digest
    public: bytes
    signature: Signature


@dataclass(frozen=True, slots=True)
class _Spend:
    name: NoteName
    proof: LockMerkleProof | None
    fee: int
    seeds: Tree | None
    outputs: tuple[OutputV1, ...]
    signatures: tuple[_SignedPKH, ...] = ()
    preimages: tuple[Noun, ...] = ()
    migration_note: NoteV0 | None = None

    @property
    def lock(self) -> LockV1 | LockV0:
        return self.migration_note.lock if self.migration_note is not None else self.proof.condition

    def signature_hash(self) -> Digest:
        return hash_cell(tree_digest(self.seeds, True), hash_atom(self.fee))

    def signature_tree(self) -> Tree | None:
        tree = None
        for signed in self.signatures:
            public, signature = public_noun(parse_point(signed.public)), signed.signature.noun()
            if self.migration_note is not None:
                digest = hash_cell(hash_noun(public), hash_noun(signature))
                node = Tree.make(public, signature, digest, digest, True)
            else:
                digest = hash_cell(signed.pkh, hash_cell(hash_noun(public), hash_noun(signature)))
                node = Tree.make(signed.pkh.noun(), Cell(public, signature), digest, digest, True)
            tree = tree_put(tree, node)
        return tree

    def witness(self) -> Noun:
        if self.migration_note is not None:
            return tree_noun(self.signature_tree())
        return noun_tuple(
            self.proof.noun(),
            tree_noun(self.signature_tree()),
            tree_noun(preimage_tree(self.preimages)),
            0,
        )

    def hash(self) -> Digest:
        if self.migration_note is not None:
            return fold_hashes(
                hash_atom(0),
                tree_digest(self.signature_tree()),
                tree_digest(self.seeds),
                hash_atom(self.fee),
            )
        witness = fold_hashes(
            self.proof.hash(),
            tree_digest(self.signature_tree()),
            tree_digest(preimage_tree(self.preimages)),
            hash_atom(0),
        )
        return fold_hashes(hash_atom(1), witness, tree_digest(self.seeds), hash_atom(self.fee))

    def noun(self) -> Noun:
        return noun_tuple(
            0 if self.migration_note is not None else 1,
            self.witness(),
            tree_noun(self.seeds),
            self.fee,
        )


def _minimum_fee(spends: tuple[_Spend, ...], parameters: FeeParameters = FeeParameters()) -> int:
    witness_words = 0
    unmerged_words = 0
    metadata: dict[Digest, dict[int, Noun]] = {}
    for spend in spends:
        spend.lock.required_pkh_policy()
        signatures = max(len(spend.signatures), spend.lock.threshold)
        if spend.migration_note is not None:
            witness_words += 1 + signatures * 30
        else:
            witness_words += (
                leaf_count(spend.proof.noun())
                + signatures * 35
                + 2
                + leaf_count(tree_noun(preimage_tree(spend.preimages)))
            )
        for output in spend.outputs:
            unmerged_words += 1 + sum(
                1 + leaf_count(v) for v in metadata_entries(output.note_data).values()
            )
            entries = metadata.setdefault(output.lock_root, {})
            for tag, value in metadata_entries(output.note_data).items():
                if tag in entries and not noun_equal(entries[tag], value):
                    raise NockchainError("conflicting output metadata for one lock")
                entries[tag] = value
    data_words = 0
    for entries in metadata.values():
        words = 1 + sum(1 + leaf_count(value) for value in entries.values())
        if words > MAX_NOTE_DATA_WORDS_V1:
            raise NockchainError("output metadata exceeds consensus word limit")
        data_words += words
    if parameters.height < parameters.bythos_phase:
        data_words = unmerged_words
    return compute_minimum_fee(data_words, witness_words, parameters).minimum_fee


_TX_TOKEN = object()


class TransactionV1:
    """Immutable unsigned, partially signed or signed transaction."""

    __slots__ = ("_spends", "_raw", "_id", "_fees", "_fund_policy")

    def __init__(
        self,
        token: object,
        spends: tuple[_Spend, ...],
        raw: Noun,
        ident: Digest,
        fees: FeeParameters,
        fund_policy: FundLockPolicy | None,
    ):
        if token is not _TX_TOKEN:
            raise NockchainError("use prepare_transaction_v1 or parse_transaction_v1")
        object.__setattr__(self, "_spends", spends)
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_id", ident)
        object.__setattr__(self, "_fees", fees)
        object.__setattr__(self, "_fund_policy", fund_policy)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("transactions are immutable")

    @property
    def id(self) -> Digest:
        """Commitment including signatures; each signature changes the ID."""
        return self._id

    def noun(self) -> Noun:
        return self._raw

    def jam(self) -> bytes:
        return jam(self._raw)

    def summary(self) -> TransactionSummaryV1:
        fees, outputs, review = 0, 0, []
        for spend in self._spends:
            fees = _add(fees, spend.fee)
            for output in spend.outputs:
                outputs = _add(outputs, output.nicks)
            signed = {signature.pkh for signature in spend.signatures}
            review.append(
                SpendSummaryV1(
                    spend.name,
                    spend.lock,
                    spend.fee,
                    spend.outputs,
                    tuple(key for key in spend.lock.keys if key in signed),
                    spend.signature_hash(),
                    spend.proof,
                )
            )
        return TransactionSummaryV1(
            self.id, fees, outputs, _minimum_fee(self._spends, self._fees), tuple(review)
        )

    def _verify(self, require_threshold: bool) -> None:
        for spend in self._spends:
            if spend.proof is not None:
                _check_unlock(spend.proof, spend.preimages)
            count = len(spend.signatures)
            if count > spend.lock.threshold or (
                require_threshold and count != spend.lock.threshold
            ):
                raise NockchainError("signature count must equal the threshold")
            for signature in spend.signatures:
                point = parse_point(signature.public)
                if (
                    public_key_hash(point) != signature.pkh
                    or signature.pkh not in spend.lock.keys
                    or not verify_digest(
                        signature.public, spend.signature_hash(), signature.signature
                    )
                ):
                    raise NockchainError("invalid or unauthorized signature")

    def verify_signatures(self, *, require_threshold: bool = True) -> None:
        """Check signatures, authorization and minimum fee; optionally allow missing signatures."""
        self._verify(require_threshold)
        review = self.summary()
        if review.fee_nicks < review.minimum_fee_nicks:
            raise NockchainError("fee below minimum")

    def sign(self, key: ExtendedKey) -> TransactionV1:
        """Add this key's authorized signatures after verifying existing ones."""
        if not key.is_private:
            raise NockchainError("private signing key required")
        self._verify(False)
        pkh = public_key_hash(key._pub)
        matched, spends = False, []
        for spend in self._spends:
            signatures = {signature.pkh: signature for signature in spend.signatures}
            if pkh in spend.lock.keys:
                matched = True
                if pkh not in signatures and len(signatures) >= spend.lock.threshold:
                    raise NockchainError("input already has its required signatures")
                signatures[pkh] = _SignedPKH(
                    pkh, key.public_bytes(), key.sign_digest(spend.signature_hash())
                )
            spends.append(replace(spend, signatures=tuple(signatures.values())))
        if not matched:
            raise NockchainError("key is not authorized by any input")
        result = _assemble(tuple(spends), self._fees, self._fund_policy)
        review = result.summary()
        if review.fee_nicks < review.minimum_fee_nicks:
            raise NockchainError("fee cannot cover additional signatures")
        return result

    def merge_signatures(self, other: TransactionV1) -> TransactionV1:
        """Merge independent signatures over identical notes, policies and outputs."""
        self._verify(False)
        other._verify(False)
        if (
            len(self._spends) != len(other._spends)
            or self._fees != other._fees
            or self._fund_policy != other._fund_policy
        ):
            raise NockchainError("different transaction plans")
        by_name = {spend.name: spend for spend in other._spends}
        spends = []
        for spend in self._spends:
            alternate = by_name.get(spend.name)
            if (
                alternate is None
                or alternate.fee != spend.fee
                or (alternate.proof is None) != (spend.proof is None)
                or not noun_equal(
                    alternate.proof.noun() if alternate.proof else alternate.migration_note.noun(),
                    spend.proof.noun() if spend.proof else spend.migration_note.noun(),
                )
                or not noun_equal(
                    tree_noun(preimage_tree(alternate.preimages)),
                    tree_noun(preimage_tree(spend.preimages)),
                )
                or not noun_equal(tree_noun(alternate.seeds), tree_noun(spend.seeds))
            ):
                raise NockchainError("different transaction plans")
            signatures = {signature.pkh: signature for signature in spend.signatures}
            for signature in alternate.signatures:
                if signature.pkh in signatures and signatures[signature.pkh] != signature:
                    raise NockchainError("conflicting signature")
                signatures[signature.pkh] = signature
            if len(signatures) > spend.lock.threshold:
                raise NockchainError("merged signatures exceed the threshold")
            spends.append(replace(spend, signatures=tuple(signatures.values())))
        result = _assemble(tuple(spends), self._fees, self._fund_policy)
        review = result.summary()
        if review.fee_nicks < review.minimum_fee_nicks:
            raise NockchainError("fee cannot cover merged signatures")
        return result

    def validate_inputs(self, notes: Iterable[NoteV1 | NoteV0], height: int) -> None:
        """Check supplied records, full parent hashes, balances and inclusive timelocks."""
        atom(height)
        notes = tuple(notes)
        if len(notes) != len(self._spends):
            raise NockchainError("input record count differs from transaction")
        by_name = {note.name: note for note in notes}
        if len(by_name) != len(notes):
            raise NockchainError("duplicate input record")
        for spend in self._spends:
            note = by_name.get(spend.name)
            if note is None:
                raise NockchainError("missing input record")
            parent = note.hash()
            if spend.migration_note is not None:
                if (
                    not isinstance(note, NoteV0)
                    or not noun_equal(note.noun(), spend.migration_note.noun())
                    or not note.admits(height)
                ):
                    raise NockchainError("migration input lock or timelock is not satisfied")
            else:
                if not isinstance(note, NoteV1):
                    raise NockchainError("input version differs from spend")
                fund = self._fund_policy
                is_fund = fund is not None and fund.authenticates(spend.proof, note.name.first)
                if not is_fund and not spend.proof.check(note.name.first):
                    raise NockchainError("lock proof does not authorize input")
                if spend.proof.full and self._fees.height < self._fees.bythos_phase:
                    raise NockchainError("full proof precedes activation")
                if is_fund and not fund.maturity.at(height).admits(note.origin_page):
                    raise NockchainError("protocol-fund input is immature")
                if (not is_fund and note.origin_page > height) or not spend.lock.allows(
                    height, note.origin_page, spend.preimages
                ):
                    raise NockchainError("input timelock or origin is not satisfied")
            total = spend.fee
            for output in spend.outputs:
                if output.parent_hash != parent:
                    raise NockchainError("output parent does not match input note")
                total = _add(total, output.nicks)
            if total != note.nicks:
                raise NockchainError("input value differs from outputs plus fee")


def _assemble(
    spends: tuple[_Spend, ...],
    fees: FeeParameters = FeeParameters(),
    fund_policy: FundLockPolicy | None = None,
) -> TransactionV1:
    if not 1 <= len(spends) <= MAX_TRANSFER_INPUTS:
        raise NockchainError("input count out of range")
    if sum(len(spend.outputs) for spend in spends) > MAX_TRANSFER_OUTPUTS:
        raise NockchainError("output count out of range")
    tree = None
    for spend in spends:
        digest = hash_cell(spend.name.hash(), spend.hash())
        tree = tree_put(tree, Tree.make(spend.name.noun(), spend.noun(), digest, digest, True))
    ident = hash_cell(hash_atom(1), tree_digest(tree))
    raw = noun_tuple(1, ident.noun(), tree_noun(tree))
    bounded_noun(raw)
    result = TransactionV1(_TX_TOKEN, spends, raw, ident, fees, fund_policy)
    result.summary()
    return result


def _check_unlock(proof: LockMerkleProof, preimages):
    condition = proof.condition
    condition.required_pkh_policy()
    tree = preimage_tree(preimages)
    supplied = {hash_each(value) for value in preimages}
    if condition._burn or any(value not in supplied for value in condition.hashes):
        raise NockchainError("burned condition or missing hashlock preimage")
    return tree


def prepare_transaction_v1(
    plans: Iterable[LockedSpendPlanV1],
    *,
    fees: FeeParameters = FeeParameters(),
    fund_policy: FundLockPolicy | None = None,
) -> TransactionV1:
    return _prepare_transaction(plans, fees, fund_policy, True)


def _prepare_transaction(plans, fees, fund_policy, check_fee):
    """Validate complete note commitments, declared balances and planned fees."""
    plans = tuple(plans)
    if not 1 <= len(plans) <= MAX_TRANSFER_INPUTS:
        raise NockchainError("input count out of range")
    seen, spends = set(), []
    for plan in plans:
        parent = plan.note.hash()
        migration = plan.note if isinstance(plan.note, NoteV0) else None
        proof = (
            None
            if migration
            else build_lock_merkle_proof(
                plan.lock, plan.leaf_number, full=fees.height >= fees.bythos_phase
            )
        )
        if migration:
            authorized = (
                isinstance(plan.lock, LockV0)
                and plan.lock.root == migration.lock.root
                and migration.name.first == note_first_v0(plan.lock, migration.timelock is not None)
                and not plan.preimages
                and plan.leaf_number == 1
            )
        else:
            fund = fund_policy is not None and fund_policy.authenticates(
                proof, plan.note.name.first
            )
            authorized = fund or proof.check(plan.note.name.first)
            _check_unlock(proof, plan.preimages)
        if not authorized or plan.note.name in seen or not plan.outputs:
            raise NockchainError("invalid, duplicate, or lock-mismatched input")
        seen.add(plan.note.name)
        roots, outputs, tree, total = set(), [], None, plan.fee
        for output in plan.outputs:
            if output.lock_root in roots:
                raise NockchainError("duplicate output lock")
            roots.add(output.lock_root)
            total = _add(total, output.nicks)
            metadata = output.metadata()
            regular = fold_hashes(
                output.lock_root, metadata_hash(metadata), hash_atom(output.nicks), parent
            )
            seed = noun_tuple(0, output.lock_root.noun(), metadata, output.nicks, parent.noun())
            tree = tree_put(
                tree, Tree.make(seed, 0, regular, hash_cell(hash_atom(0), regular), False)
            )
            outputs.append(OutputV1(output.lock_root, metadata, output.nicks, parent))
        if total != plan.note.nicks:
            raise NockchainError("input value differs from outputs plus fee")
        spends.append(
            _Spend(
                plan.note.name,
                proof,
                plan.fee,
                tree,
                tuple(outputs),
                preimages=plan.preimages,
                migration_note=migration,
            )
        )
    transaction = _assemble(tuple(spends), fees, fund_policy)
    review = transaction.summary()
    if check_fee and review.fee_nicks < review.minimum_fee_nicks:
        raise NockchainError(f"fee below minimum {review.minimum_fee_nicks} nicks")
    return transaction


def minimum_transaction_fee_v1(
    inputs: Iterable[LockFormV1 | LockMerkleProof],
    outputs: Iterable[LockFormV1],
    fees: FeeParameters = FeeParameters(),
) -> int:
    inputs, outputs = tuple(inputs), tuple(outputs)
    if not 1 <= len(inputs) <= MAX_TRANSFER_INPUTS or not 1 <= len(outputs) <= MAX_TRANSFER_OUTPUTS:
        raise NockchainError("transaction size out of range")
    zero = Digest((0,) * 5)
    spends = tuple(
        _Spend(
            NoteName(zero, zero),
            lock
            if isinstance(lock, LockMerkleProof)
            else build_lock_merkle_proof(lock, full=fees.height >= fees.bythos_phase),
            0,
            None,
            (),
        )
        for lock in inputs
    )
    spends = (
        replace(
            spends[0],
            outputs=tuple(OutputV1(lock.root, lock.metadata(), 0, zero) for lock in outputs),
        ),
        *spends[1:],
    )
    return _minimum_fee(spends, fees)


def _parse_public(noun: Noun) -> bytes:
    x, y, marker = parts(noun, 3)
    if marker != 1:
        raise NockchainError("invalid public point marker")
    encoded = b"\x01" + b"".join(
        atom(value).to_bytes(8, "big")
        for coordinate in (y, x)
        for value in reversed(parts(coordinate, 6))
    )
    parse_point(encoded)
    return encoded


def _parse_signature(noun: Noun) -> Signature:
    challenge, response = parts(noun, 2)
    result = Signature(tuple(parts(challenge, 8)), tuple(parts(response, 8)))
    if not result._valid():
        raise NockchainError("invalid signature scalar")
    return result


def parse_transaction_v1(
    data: bytes,
    *,
    fees: FeeParameters = FeeParameters(),
    fund_policy: FundLockPolicy | None = None,
    migration_notes: Iterable[NoteV0] = (),
) -> TransactionV1:
    """Decode supported canonical V1 structures and check the embedded ID.

    Signature and authenticated input/height validation are separate operations.
    """
    raw = cue(data)
    bounded_noun(raw)
    version, embedded, spend_map = parts(raw, 3)
    if version != 1:
        raise NockchainError("unsupported transaction version")
    embedded = noun_digest(embedded)
    spends = []
    migration_by_name = {}
    for note in migration_notes:
        if not isinstance(note, NoteV0) or note.name in migration_by_name:
            raise NockchainError("invalid or duplicate migration input")
        migration_by_name[note.name] = note

    def parse_spend(key: Noun, value: Noun) -> tuple[Digest, Digest]:
        first, last, terminator = parts(key, 3)
        if terminator != 0:
            raise NockchainError("invalid note name")
        name = NoteName(noun_digest(first), noun_digest(last))
        version, witness, seeds_noun, fee = parts(value, 4)
        migration = None
        if version == 0:
            migration = migration_by_name.get(name)
            if migration is None:
                raise NockchainError("complete migration input required for inspection")
            if migration.name.first != note_first_v0(
                migration.lock, migration.timelock is not None
            ):
                raise NockchainError("migration input name does not bind its lock")
            proof, lock, signature_map, preimages = None, migration.lock, witness, ()
        elif version == 1:
            proof_noun, signature_map, hax, time = parts(witness, 4)
            if time != 0:
                raise NockchainError("witness tim must be zero")
            proof = LockMerkleProof.from_noun(proof_noun)
            lock = proof.condition
            fund = fund_policy is not None and fund_policy.authenticates(proof, name.first)
            if not fund and not proof.check(name.first):
                raise NockchainError("lock proof does not authorize input")
            if proof.full and fees.height < fees.bythos_phase:
                raise NockchainError("full proof precedes activation")
            preimages = parse_preimages(hax)
            _check_unlock(proof, preimages)
        else:
            raise NockchainError("unsupported spend version")
        signatures, outputs = [], []

        def parse_signed(key: Noun, value: Noun) -> tuple[Digest, Digest]:
            if migration is not None:
                public, signature = key, value
                pkh = hash_noun(public)
            else:
                pkh = noun_digest(key)
                public, signature = parts(value, 2)
            encoded = _parse_public(public)
            sig = _parse_signature(signature)
            if hash_noun(public) != pkh or pkh not in lock.keys:
                raise NockchainError("unauthorized signature key")
            signatures.append(_SignedPKH(pkh, encoded, sig))
            digest = (
                hash_cell(pkh, hash_noun(signature))
                if migration is not None
                else hash_cell(pkh, hash_cell(hash_noun(public), hash_noun(signature)))
            )
            return digest, digest

        read_tree(signature_map, True, 32, parse_signed)
        if seeds_noun == 0:
            raise NockchainError("each input requires an output seed")

        def parse_seed(key: Noun, value: Noun) -> tuple[Digest, Digest]:
            source, root, metadata, amount, parent = parts(key, 5)
            if source != 0:
                raise NockchainError("unsupported source-constrained output")
            root, parent, amount = noun_digest(root), noun_digest(parent), atom(amount)
            if amount == 0:
                raise NockchainError("zero output seed")
            digest = fold_hashes(root, metadata_hash(metadata), hash_atom(amount), parent)
            outputs.append(OutputV1(root, metadata, amount, parent))
            return digest, hash_cell(hash_atom(0), digest)

        tree = read_tree(seeds_noun, False, MAX_TRANSFER_OUTPUTS, parse_seed)
        spend = _Spend(
            name, proof, atom(fee), tree, tuple(outputs), tuple(signatures), preimages, migration
        )
        spends.append(spend)
        digest = hash_cell(name.hash(), spend.hash())
        return digest, digest

    read_tree(spend_map, True, MAX_TRANSFER_INPUTS, parse_spend)
    transaction = _assemble(tuple(spends), fees, fund_policy)
    if transaction.id != embedded:
        raise NockchainError("transaction ID does not match contents")
    return transaction
