from dataclasses import replace
from pathlib import Path
import unittest
import json

from nockchain._core import Cell, Digest, NockchainError, cue, jam, noun_digest, parts
from nockchain.locks import LockV1, note_first_v1
from nockchain.lock_tree import (
    LockTreeV1,
    LockMerkleProof,
    authorization_leaf,
    build_lock_merkle_proof,
    parse_lock,
    valid_stub_axis,
)
from nockchain.note_data import NoteData
from nockchain.fee import FeeParameters, compute_minimum_fee, transaction_words

FIXTURES = Path(__file__).parents[1] / "testdata" / "wallet"


def rows(noun):
    while isinstance(noun, Cell):
        yield noun.head
        noun = noun.tail
    if noun != 0:
        raise ValueError("improper list")


def vectors():
    return json.loads((FIXTURES / "reference.json").read_text())


def decode(value):
    return cue(bytes.fromhex(value))


def digest(value):
    return Digest(int(v) for v in value)


class WalletReferenceTests(unittest.TestCase):
    def test_fee_and_bridge_bounds(self):
        from nockchain import BridgeDepositDataPayload, compute_bridge_fee, noun_tuple, PRIME

        maximum = (1 << 64) - 1
        self.assertEqual(
            compute_minimum_fee(0, 2, FeeParameters(base_fee=maximum, min_fee=0)).minimum_fee,
            maximum // 4,
        )
        self.assertEqual(
            compute_minimum_fee(
                2, 0, FeeParameters(height=0, base_fee=maximum, min_fee=0)
            ).minimum_fee,
            maximum,
        )
        self.assertEqual(compute_bridge_fee(65_537, 7), 14)
        self.assertEqual(compute_bridge_fee(0, maximum), 0)
        self.assertEqual(compute_bridge_fee(maximum, maximum), maximum)
        payload = BridgeDepositDataPayload(bytes([255]) * 20)
        self.assertEqual(BridgeDepositDataPayload.from_noun(payload.noun()), payload)
        with self.assertRaises(NockchainError):
            BridgeDepositDataPayload(bytes(21))
        with self.assertRaises(NockchainError):
            BridgeDepositDataPayload.from_noun(noun_tuple(0, 0x65736162, 0, 0, PRIME - 1))

    def test_canonical_sharing_and_expansion_limit(self):
        cell = Cell(42, 43)
        self.assertEqual(jam(Cell(cell, cell)), jam(Cell(Cell(42, 43), Cell(42, 43))))
        for _ in range(21):
            cell = Cell(cell, cell)
        with self.assertRaises(NockchainError):
            jam(cell)
        cyclic = Cell(0, 0)
        object.__setattr__(cyclic, "tail", cyclic)
        with self.assertRaises(NockchainError):
            jam(cyclic)

    def test_canonical_jam_matches_official_payloads(self):
        data = vectors()
        payloads = [row["jam"] for row in data["raw"]]
        payloads += [row["data"] for row in data["noteData"]]
        payloads += [row["spends"] for row in data["fees"] + data["withdrawals"]]
        for row in data["locks"]:
            payloads.append(row["form"])
            payloads.extend(p[k] for p in row["proofs"] for k in ("stub", "full"))
        for payload in payloads:
            self.assertEqual(jam(decode(payload)).hex(), payload)

    def test_every_tagged_lock_leaf_matches_hoon(self):
        count = 0
        for arity, row in zip((1, 2, 4, 8, 16), vectors()["locks"]):
            lock = parse_lock(decode(row["form"]))
            self.assertEqual(lock.root, digest(row["root"]))
            self.assertEqual(jam(lock.noun()).hex(), row["form"])
            for row in row["proofs"]:
                for complete, key in ((False, "stub"), (True, "full")):
                    proof = build_lock_merkle_proof(lock, row["index"], full=complete)
                    self.assertEqual(jam(proof.noun()).hex(), row[key])
                    self.assertEqual(proof.hash(), digest(row[key + "Hash"]))
                    self.assertEqual(proof.check(note_first_v1(lock.root)), row[key + "Valid"])
                    self.assertEqual(
                        jam(LockMerkleProof.from_noun(decode(row[key])).noun()).hex(), row[key]
                    )
                    self.assertEqual(valid_stub_axis(proof), complete or arity == 1)
                    self.assertTrue(valid_stub_axis(proof, True))
                    self.assertFalse(replace(proof, axis=0).check(note_first_v1(lock.root)))
                    self.assertFalse(
                        replace(proof, path=proof.path + (lock.root,)).check(
                            note_first_v1(lock.root)
                        )
                    )
                    if proof.path:
                        self.assertFalse(
                            replace(proof, path=proof.path[:-1]).check(note_first_v1(lock.root))
                        )
                self.assertTrue(authorization_leaf(proof.axis, proof.path))
                count += 1
        self.assertEqual(count, 31)

    def test_note_data_hashes_and_words_match_hoon(self):
        for row in vectors()["noteData"]:
            data = NoteData.from_noun(decode(row["data"]))
            self.assertEqual(data.hash(), digest(row["hash"]), row["case"])
            self.assertEqual(data.words(), int(row["words"]), row["case"])
            self.assertEqual(jam(data.noun()).hex(), row["data"], row["case"])
            for entry in data.decoded():
                payload = entry.payload
                value = payload.noun() if hasattr(payload, "noun") else payload
                self.assertEqual(jam(value), jam(dict(data.entries)[entry.key]), row["case"])

    def test_fee_counts_match_hoon_before_at_and_after_activation(self):
        for row in vectors()["fees"]:
            height, base, divisor, minimum, seed, witness, expected = (
                int(row[k])
                for k in (
                    "height",
                    "base",
                    "divisor",
                    "minimum",
                    "seedWords",
                    "witnessWords",
                    "fee",
                )
            )
            words = transaction_words(decode(row["spends"]), merge_by_lock_root=height >= 10)
            self.assertEqual((words.seed_words, words.witness_words), (seed, witness))
            fee = compute_minimum_fee(
                seed, witness, FeeParameters(height, 10, base, divisor, minimum)
            )
            self.assertEqual(fee.minimum_fee, expected)
        self.assertEqual(len(vectors()["fees"]), 12)
        for row in vectors()["withdrawals"]:
            words = transaction_words(
                decode(row["spends"]),
                merge_by_lock_root=int(row["height"]) >= 10,
                estimate_signatures=True,
            )
            self.assertEqual(
                (words.seed_words, words.witness_words),
                (int(row["seedWords"]), int(row["witnessWords"])),
            )
            fee = compute_minimum_fee(
                words.seed_words,
                words.witness_words,
                FeeParameters(int(row["height"]), 10, 256, 4, 0),
            )
            self.assertEqual(fee.minimum_fee, int(row["fee"]))

    def test_lock_boundaries_and_padding(self):
        lock = parse_lock(decode(vectors()["locks"][0]["form"]))
        self.assertIsInstance(lock, LockV1)
        tree = LockTreeV1((lock, lock, lock))
        self.assertEqual(len(tree.conditions), 4)
        self.assertFalse(tree.conditions[3].allows(100, 0))
        for bad in (0, 5, True):
            with self.assertRaises(NockchainError):
                build_lock_merkle_proof(tree, bad)
        with self.assertRaises(NockchainError):
            parse_lock(0)
        with self.assertRaises(NockchainError):
            LockV1.from_noun(0)

    def test_plans_match_pinned_rust_core_bytes(self):
        import nockchain as n

        def name(value):
            first, last, zero = parts(decode(value), 3)
            self.assertEqual(zero, 0)
            return n.NoteName(noun_digest(first), noun_digest(last))

        def output(value):
            return n.PlannedOutput(
                digest(value["root"]), decode(value["data"]), int(value["amount"])
            )

        for row in vectors()["plans"]:
            candidates = []
            for wire in row["candidates"]:
                version, origin, ident, data, amount = parts(decode(wire), 5)
                self.assertEqual(version, 1)
                first, last, zero = parts(ident, 3)
                candidates.append(
                    n.NoteV1(
                        origin, n.NoteName(noun_digest(first), noun_digest(last)), data, amount
                    )
                )
            result = n.plan(
                n.PlanRequest(
                    tuple(candidates),
                    tuple(output(o) for o in row["outputs"]),
                    output(row["refund"]),
                    n.ChainContext.at_height(int(row["height"])),
                    None if row["selection"] is None else tuple(name(v) for v in row["selection"]),
                    row["order"],
                    None if row["exactFee"] is None else int(row["exactFee"]),
                    None if row["sweep"] is None else output(row["sweep"]),
                ),
                n.SigningKeyLockMatcher(digest(row["signer"])),
            )
            self.assertEqual(result.transaction.jam().hex(), row["jam"], row["case"])
            self.assertEqual(
                tuple(note.name for note in result.selected),
                tuple(name(v) for v in row["selected"]),
            )
            self.assertEqual(result.selected_total, int(row["selectedTotal"]))
            self.assertEqual(result.final_fee, int(row["fee"]))
            self.assertEqual(result.minimum_fee, int(row["minimumFee"]))
            self.assertEqual(
                (result.word_counts.seed_words, result.word_counts.witness_words),
                (int(row["seedWords"]), int(row["witnessWords"])),
            )
            self.assertEqual(
                result.refunds, tuple((name(r["name"]), int(r["amount"])) for r in row["refunds"])
            )

    def test_migration_plans_and_signatures_match_rust_core(self):
        import nockchain as n
        from test_protocol import key_for

        def output(value):
            return n.PlannedOutput(
                digest(value["root"]), decode(value["data"]), int(value["amount"])
            )

        for row in vectors()["migrations"]:
            notes = tuple(n.NoteV0.from_noun(decode(value)) for value in row["candidates"])
            for note, wire, parent in zip(notes, row["candidates"], row["parents"]):
                self.assertEqual(jam(note.noun()).hex(), wire)
                self.assertEqual(note.hash(), digest(parent))
            result = n.plan(
                n.PlanRequest(
                    notes,
                    tuple(output(o) for o in row["outputs"]),
                    output(row["refund"]),
                    n.ChainContext.at_height(int(row["height"])),
                    sweep=None if row["sweep"] is None else output(row["sweep"]),
                    version=0,
                ),
                n.SigningKeyLockMatcher(digest(row["signer"])),
            )
            self.assertEqual(result.transaction.jam().hex(), row["jam"], row["case"])
            self.assertEqual(result.final_fee, int(row["fee"]))
            self.assertEqual(result.minimum_fee, int(row["minimumFee"]))
            self.assertEqual(
                (result.word_counts.seed_words, result.word_counts.witness_words),
                (int(row["seedWords"]), int(row["witnessWords"])),
            )
            signed = result.transaction.sign(key_for(row["seed"], ()))
            self.assertEqual(signed.jam().hex(), row["signedJam"], row["case"])
            signed.verify_signatures()
            signed.validate_inputs(result.selected, int(row["height"]))
            with self.assertRaises(n.NockchainError):
                n.parse_transaction_v1(signed.jam())
            parsed = n.parse_transaction_v1(
                signed.jam(), fees=n.FeeParameters(height=int(row["height"])), migration_notes=notes
            )
            parsed.verify_signatures()
            parsed.validate_inputs(result.selected, int(row["height"]))
            self.assertEqual(parsed.jam(), signed.jam())
            self.assertEqual(parsed.merge_signatures(signed).jam(), signed.jam())
            changed = tuple(
                replace(note, source=n.Digest((1, 2, 3, 4, 5))) for note in result.selected
            )
            with self.assertRaises(n.NockchainError):
                signed.validate_inputs(changed, int(row["height"]))
