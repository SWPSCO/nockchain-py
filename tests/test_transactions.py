import json
import random
from dataclasses import replace
import unittest

import nockchain as n
from nockchain._core import parts, leaf_count
from nockchain.transaction import _Spend, _minimum_fee
from test_protocol import DATA, REFERENCE, key_for

CONSENSUS = json.loads((DATA / "consensus.json").read_text())
ORACLE = {v["id"]: v for v in CONSENSUS["transactions"]}


def note_from(v):
    return n.NoteV1(
        v["originPage"],
        n.NoteName(n.Digest(v["name"]["first"]), n.Digest(v["name"]["last"])),
        0,
        v["nicks"],
    )


def lock_from(v):
    time = n.TimelockV1(n.HeightRange(5, 50), n.HeightRange(100, 200)) if v["timed"] else None
    return n.LockV1(2, tuple(n.Digest(k) for k in v["keys"]), time)


class TransactionTests(unittest.TestCase):
    def test_single_key_wire_and_hoon_oracle(self):
        self.assertEqual(CONSENSUS["commit"], "1eac02083a053c104b6a1299e80a8a51447017dc")
        for v in REFERENCE["transactions"]:
            plans = tuple(
                n.SpendPlanV1(
                    note_from(p["note"]),
                    n.Digest(p["lockRoot"]),
                    tuple(n.PaymentV1(n.Digest(o["recipient"]), o["nicks"]) for o in p["outputs"]),
                    p["fee"],
                )
                for p in v["plans"]
            )
            tx = key_for(v["seed"], ()).sign_transfer_v1(plans)
            self.assertEqual(tx.jam().hex(), v["jam"])
            self.assertEqual(str(tx.id), v["id"])
            self.assertEqual(tx.summary().minimum_fee_nicks, ORACLE[v["id"]]["minimumFee"])
            notes = tuple(p.note for p in plans)
            self.assertEqual(
                [tuple(note.hash()) for note in notes],
                [tuple(h) for h in ORACLE[v["id"]]["parentHashes"]],
            )
            parsed = n.parse_transaction_v1(tx.jam())
            self.assertEqual(parsed.jam(), tx.jam())
            parsed.verify_signatures()
            parsed.validate_inputs(notes, 105)
            for spend in parsed.summary().spends:
                for output in spend.outputs:
                    self.assertEqual(output.lock().root, output.lock_root)

    def test_multisig_and_timelocks(self):
        for v in REFERENCE["multisig"]:
            lock, note = lock_from(v), note_from(v["note"])
            self.assertEqual(lock.root, n.Digest(v["root"]))
            self.assertEqual(note.hash(), n.Digest(v["parent"]))
            keys = [key_for(seed, ()) for seed in v["seeds"]]
            plan = n.LockedSpendPlanV1(note, lock, (n.LockedPaymentV1(lock, v["gift"]),), v["fee"])
            unsigned = n.prepare_transaction_v1([plan])
            with self.assertRaises(n.NockchainError):
                unsigned.verify_signatures()
            a = unsigned.sign(keys[0])
            self.assertEqual(a.jam().hex(), v["partialJam"])
            with self.assertRaises(n.NockchainError):
                a.verify_signatures()
            a = n.parse_transaction_v1(a.jam())
            b = unsigned.sign(keys[1])
            signed = a.merge_signatures(b)
            self.assertEqual(signed.jam().hex(), v["jam"])
            self.assertEqual(str(signed.id), v["id"])
            self.assertEqual(signed.summary().minimum_fee_nicks, ORACLE[v["id"]]["minimumFee"])
            self.assertEqual(
                n.minimum_transaction_fee_v1([lock], [lock]), ORACLE[v["id"]]["minimumFee"]
            )
            signed.verify_signatures()
            parsed = n.parse_transaction_v1(signed.jam())
            parsed.verify_signatures()
            parsed.validate_inputs([note], 105)
            if v["timed"]:
                for height in (99, 100, 104, 151, 201):
                    with self.assertRaises(n.NockchainError):
                        parsed.validate_inputs([note], height)
                parsed.validate_inputs([note], 150)
            for bad in (
                replace(note, origin_page=note.origin_page + 1),
                replace(note, nicks=note.nicks + 1),
            ):
                with self.assertRaises(n.NockchainError):
                    parsed.validate_inputs([bad], 110)
            with self.assertRaises(n.NockchainError):
                signed.sign(keys[2])
            with self.assertRaises(n.NockchainError):
                signed.merge_signatures(unsigned.sign(keys[2]))
            self.assertEqual(signed.sign(keys[0]).jam(), signed.jam())
            self.assertEqual(len(unsigned.summary().spends[0].signed_keys), 0)
            self.assertEqual(len(a.summary().spends[0].signed_keys), 1)
            different = n.prepare_transaction_v1(
                [replace(plan, fee=plan.fee + 1, outputs=(n.LockedPaymentV1(lock, v["gift"] - 1),))]
            )
            with self.assertRaises(n.NockchainError):
                a.merge_signatures(different.sign(keys[1]))
            with self.assertRaises(AttributeError):
                signed.summary().spends[0].outputs[0].nicks = 1

    def test_selection_change_and_fee_gap(self):
        key = key_for(REFERENCE["keys"][0]["seed"], ())
        pkh = n.parse_digest(key.address())
        root = n.lock_root(pkh)

        def note(amount, last):
            return n.UnspentNote(
                n.NoteV1(
                    100, n.NoteName(n.note_first_v1(root), n.Digest([last, 2, 3, 4, 5])), 0, amount
                ),
                root,
            )

        destination = REFERENCE["keys"][1]["address"]
        notes = [note(1_000_000, 1), note(4_000_000, 2), note(2_000_000, 3)]
        selected = n.select_transfer(
            key.public(), notes, [n.Payment(destination, n.format_nocks(1_000_000))]
        )
        self.assertEqual(selected.summary().input_count, 1)
        self.assertEqual(selected.notes()[0].nicks, 4_000_000)
        signed = selected.sign(key)
        signed.verify_signatures()
        signed.validate_inputs(selected.notes(), 100)
        self.assertEqual(notes[0].note.nicks, 1_000_000)
        fee = n.minimum_transfer_fee_v1(1, [n.parse_digest(destination)])
        gap_note = note(1_000_000 + fee + 10, 4)
        gap = n.prepare_transfer(
            key.public(), [gap_note], [n.Payment(destination, n.format_nocks(1_000_000))]
        )
        self.assertEqual(gap.summary().change_nicks, 0)
        self.assertEqual(gap.summary().fee_nicks, fee + 10)
        gap.sign(key).verify_signatures()
        with self.assertRaises(n.NockchainError):
            selected.sign(key.child(1))
        with self.assertRaises(n.NockchainError):
            n.select_transfer(key, [notes[0], notes[0]], [n.Payment(destination, "1")])

    def test_metadata_and_nonempty_seed(self):
        v = REFERENCE["multisig"][0]
        lock, note = lock_from(v), note_from(v["note"])
        with self.assertRaises(n.NockchainError):
            n.prepare_transaction_v1([n.LockedSpendPlanV1(note, lock, (), note.nicks)])
        full = replace(note, note_data=lock.metadata())
        tx = n.prepare_transaction_v1(
            [n.LockedSpendPlanV1(full, lock, (n.LockedPaymentV1(lock, v["gift"]),), v["fee"])]
        )
        tx.validate_inputs([full], 100)
        with self.assertRaises(n.NockchainError):
            tx.validate_inputs([note], 100)
        metadata = n.noun_tuple(n.Cell(1, 2), 0, 0)
        output = n.OutputV1(lock.root, metadata, 1, note.hash())
        spend = _Spend(note.name, lock, 0, None, (output,))
        expected = 3 * (1 << 14) + (leaf_count(lock._proof()) + 73) * (1 << 12)
        self.assertEqual(_minimum_fee((spend,)), expected)
        self.assertEqual(_minimum_fee((replace(spend, outputs=(output, output)),)), expected)
        conflicting = replace(output, note_data=n.noun_tuple(n.Cell(1, 3), 0, 0))
        with self.assertRaises(n.NockchainError):
            _minimum_fee((replace(spend, outputs=(output, conflicting)),))
        large = 0
        for _ in range(11):
            large = n.Cell(large, large)
        oversized = replace(output, note_data=n.noun_tuple(n.Cell(1, large), 0, 0))
        with self.assertRaises(n.NockchainError):
            _minimum_fee((replace(spend, outputs=(oversized,)),))

    def test_malformed_and_random_inputs(self):
        v = REFERENCE["transactions"][0]
        wire = bytes.fromhex(v["jam"])
        root = list(parts(n.cue(wire), 3))
        root[1] = n.Digest([1, 2, 3, 4, 5]).noun()
        malformed = [wire[:-1], wire + b"\0", n.jam(n.noun_tuple(*root)), n.jam(0)]
        tree = parts(n.cue(wire), 3)[2]
        entry, left, right = parts(tree, 3)
        name, spend = parts(entry, 2)
        version, witness, seeds, fee = parts(spend, 4)
        proof, signatures, hax, time = parts(witness, 4)
        tag, condition, axis, commitment = parts(proof, 4)
        for altered_proof in (
            n.noun_tuple(tag, condition, 2, commitment),
            n.noun_tuple(123, condition, axis, commitment),
        ):
            altered_spend = n.noun_tuple(
                version, n.noun_tuple(altered_proof, signatures, hax, time), seeds, fee
            )
            malformed.append(
                n.jam(
                    n.noun_tuple(
                        1,
                        n.parse_digest(v["id"]).noun(),
                        n.noun_tuple(n.Cell(name, altered_spend), left, right),
                    )
                )
            )
        for data in malformed:
            with self.assertRaises(n.NockchainError):
                n.parse_transaction_v1(data)
        rng = random.Random(0xC0FFEE)
        for _ in range(250):
            data = rng.randbytes(rng.randrange(1, 128))
            try:
                noun = n.cue(data)
            except n.NockchainError:
                continue
            self.assertTrue(n.noun_equal(noun, n.cue(n.jam(noun))))
            try:
                n.parse_transaction_v1(data)
            except n.NockchainError:
                pass


if __name__ == "__main__":
    unittest.main()
