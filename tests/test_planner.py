from dataclasses import replace
import unittest

import nockchain as n
from nockchain._core import hash_each
from test_protocol import REFERENCE, key_for


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.key = key_for(REFERENCE["keys"][0]["seed"], ())
        self.pkh = n.parse_digest(self.key.address())
        self.lock = n.LockV1(1, (self.pkh,))
        self.refund = n.PlannedOutput(self.lock.root, self.lock.metadata(), 0)
        self.payment = n.PlannedOutput.payment(n.Digest((7, 8, 9, 10, 11)), 1_000_000)

    def note(self, amount, last=1, lock=None, origin=100):
        lock = lock or self.lock
        return n.NoteV1(
            origin,
            n.NoteName(n.note_first_v1(lock.root), n.Digest((last, 2, 3, 4, 5))),
            lock.metadata(),
            amount,
        )

    def test_selection_fee_conservation_and_wire(self):
        notes = (self.note(2_000_000, 1), self.note(4_000_000, 2))
        request = n.PlanRequest(
            notes, (self.payment,), self.refund, n.ChainContext.at_height(54_000)
        )
        result = n.plan(request, n.SigningKeyLockMatcher(self.pkh))
        self.assertEqual(result.selected, (notes[1],))
        self.assertEqual(
            result.selected_total, sum(o.amount for o in result.outputs) + result.final_fee
        )
        signed = result.transaction.sign(self.key)
        signed.verify_signatures()
        signed.validate_inputs(result.selected, 54_000)
        parsed = n.parse_transaction_v1(signed.jam())
        self.assertEqual(parsed.jam(), signed.jam())
        before = n.plan(
            replace(request, chain=n.ChainContext.at_height(53_999)),
            n.SigningKeyLockMatcher(self.pkh),
        )
        self.assertGreater(before.minimum_fee, result.minimum_fee)
        self.assertFalse(before.transaction.summary().spends[0].proof.full)
        with self.assertRaises(n.NockchainError):
            n.plan(
                replace(request, selection=(notes[0].name, notes[0].name)),
                n.SigningKeyLockMatcher(self.pkh),
            )

    def test_tagged_hashlock_requires_preimage_and_preserves_change_tree(self):
        claim = n.LockV1(1, (self.pkh,), hashes=(hash_each(42),))
        tree = n.LockTreeV1((claim, self.lock))
        note = self.note(8_000_000, lock=tree)
        refund = n.PlannedOutput(tree.root, tree.metadata(), 0)
        request = n.PlanRequest((note,), (self.payment,), refund, n.ChainContext.at_height(170_000))
        with self.assertRaises(n.NockchainError):
            n.plan(request, n.LockRootLockMatcher(tree.root, tree))
        matcher = n.LockRootLockMatcher(tree.root, tree, preimages=(42,))
        result = n.plan(request, matcher)
        signed = result.transaction.sign(self.key)
        signed.verify_signatures()
        signed.validate_inputs(result.selected, 170_000)
        parsed = n.parse_transaction_v1(signed.jam())
        self.assertEqual(parsed.jam(), signed.jam())
        self.assertEqual(parsed.summary().spends[0].proof.axis, 6)
        change = next(
            output for output in parsed.summary().spends[0].outputs if output.lock_root == tree.root
        )
        self.assertEqual(change.lock().root, tree.root)
        self.assertIsInstance(change.lock(), n.LockTreeV1)
        with self.assertRaises(n.NockchainError):
            n.plan(replace(request, chain=n.ChainContext.at_height(53_999)), matcher)

    def test_fund_maturity_uses_authoritative_identity_and_candidate_height(self):
        policy = n.FundLockPolicy(
            self.lock.root, n.Digest((99, 2, 3, 4, 5)), n.FundMaturityPolicy(170_000, 100)
        )
        note = replace(
            self.note(5_000_000, origin=169_950),
            name=n.NoteName(policy.firstname, n.Digest((1, 2, 3, 4, 5))),
        )
        request = n.PlanRequest(
            (note,), (self.payment,), self.refund, n.ChainContext.at_height(169_999)
        )
        matcher = n.LockRootLockMatcher(self.lock.root, self.lock, fund_policy=policy)
        n.plan(request, matcher)
        n.plan(
            replace(request, chain=n.ChainContext(169_999, n.FeeParameters(height=170_000))),
            matcher,
        )
        with self.assertRaises(n.NockchainError):
            n.plan(
                replace(request, chain=n.ChainContext(170_000, n.FeeParameters(height=169_999))),
                matcher,
            )
        with self.assertRaises(n.NockchainError):
            n.plan(replace(request, chain=n.ChainContext.at_height(170_000)), matcher)
        mature = n.plan(replace(request, chain=n.ChainContext.at_height(170_050)), matcher)
        signed = mature.transaction.sign(self.key)
        signed.validate_inputs((note,), 170_050)
        self.assertTrue(n.FundMaturity(10, None).admits(11))
        self.assertFalse(n.FundMaturity(10, 0).admits(11))
        with self.assertRaises(n.NockchainError):
            n.parse_transaction_v1(signed.jam())
        parsed = n.parse_transaction_v1(signed.jam(), fund_policy=policy)
        parsed.validate_inputs((note,), 170_050)

    def test_sweep_and_manual_inputs_use_one_planner(self):
        notes = (self.note(3_000_000, 1), self.note(4_000_000, 2))
        request = n.PlanRequest(
            notes,
            (),
            self.refund,
            n.ChainContext.at_height(54_000),
            order="ascending",
            sweep=replace(self.payment, amount=0),
        )
        result = n.plan(request, n.SigningKeyLockMatcher(self.pkh))
        self.assertEqual(result.selected, notes)
        self.assertEqual(result.refunds, ())
        self.assertEqual(sum(o.amount for o in result.outputs) + result.final_fee, 7_000_000)
        self.assertTrue(all(spend.outputs for spend in result.transaction.summary().spends))
