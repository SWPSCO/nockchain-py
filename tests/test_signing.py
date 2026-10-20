import base64
import copy
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import nockchain as n
from nockchain.cli import main

FIXTURE = json.loads((Path(__file__).parent.parent / "testdata/signing-bundles.json").read_text())
SAMPLE = FIXTURE["cases"][0]["response"]["bundle"]
KEY = n.master(bytes.fromhex(FIXTURE["seed"]))


def note(record):
    return n.NoteV1(
        int(record["originPage"]),
        n.NoteName(
            n.parse_digest(record["name"]["firstName"]), n.parse_digest(record["name"]["lastName"])
        ),
        n.cue(base64.b64decode(record["noteData"])),
        int(record["amountNicks"]),
    )


class SigningTests(unittest.TestCase):
    def test_rust_bundles_match_review_and_signed_bytes(self):
        for case in FIXTURE["cases"]:
            with self.subTest(case=case["name"]):
                bundle, review = case["response"]["bundle"], case["response"]["review"]
                checked = n.inspect_signing_bundle(bundle)
                for field in ("transactionId", "feeNicks", "minimumFeeNicks"):
                    self.assertEqual(checked.review[field], review[field])
                self.assertFalse(checked.review["fullySigned"])
                signed = n.sign_signing_bundle(bundle, KEY)
                self.assertEqual(signed["rawTransaction"], case["signedRawTransaction"])
                signed_review = n.inspect_signing_bundle(signed).review
                self.assertEqual(signed_review["transactionId"], case["signedTransactionId"])
                self.assertTrue(signed_review["fullySigned"])
                self.assertNotEqual(signed_review["transactionId"], review["transactionId"])

    def test_rejects_altered_intent_commitments_and_encoding(self):
        mutations = (
            lambda b: b["payments"][0].update(amountNicks="999999"),
            lambda b: b["payments"][0].update(address=str(n.Digest((1, 2, 3, 4, 5)))),
            lambda b: b["inputs"][0].update(amountNicks="40000001"),
            lambda b: b["inputs"][0].update(originPage="53899"),
            lambda b: b["inputs"][0].update(noteData=base64.b64encode(n.jam(0)).decode()),
            lambda b: b.update(sourceAddress=b["payments"][0]["address"]),
            lambda b: b.update(rawTransaction=b["rawTransaction"] + "\n"),
            lambda b: b.update(
                rawTransaction=base64.b64encode(
                    base64.b64decode(b["rawTransaction"]) + b"\0"
                ).decode()
            ),
            lambda b: b.update(candidateHeight="18446744073709551616"),
            lambda b: b["payments"][0].update(amountNicks="01"),
            lambda b: b.update(inputs=[]),
            lambda b: b["inputs"][0].update(privateKey="unexpected"),
            lambda b: b.update(network="mainnet\nPAY SOMEBODY ELSE"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(n.NockchainError):
                bundle = copy.deepcopy(SAMPLE)
                mutate(bundle)
                n.inspect_signing_bundle(bundle)
        wrong = n.master(bytes([42]) * 64)
        for key in (wrong, KEY.public()):
            with self.assertRaisesRegex(n.NockchainError, "source address"):
                n.sign_signing_bundle(SAMPLE, key)

    def test_canonical_transaction_cannot_raise_the_planned_fee(self):
        bundle = copy.deepcopy(SAMPLE)
        checked = n.inspect_signing_bundle(bundle)
        spend = checked.transaction.summary().spends[0]
        source_root = n.LockV1(1, (n.parse_digest(bundle["sourceAddress"]),)).root
        changed = n.prepare_transaction_v1(
            (
                n.LockedSpendPlanV1(
                    note(bundle["inputs"][0]),
                    spend.lock,
                    tuple(
                        n.LockedPaymentV1(
                            output.lock(),
                            output.nicks - (1 if output.lock_root == source_root else 0),
                            output.note_data,
                        )
                        for output in spend.outputs
                    ),
                    spend.fee + 1,
                ),
            ),
            fees=n.FeeParameters(height=int(bundle["candidateHeight"])),
        )
        changed.validate_inputs(tuple(map(note, bundle["inputs"])), int(bundle["candidateHeight"]))
        changed.verify_signatures(require_threshold=False)
        bundle["rawTransaction"] = base64.b64encode(changed.jam()).decode()
        with self.assertRaisesRegex(n.NockchainError, "fee differs"):
            n.inspect_signing_bundle(bundle)

    def test_cli_inspect_and_approval_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path, output_path = (
                Path(directory) / "bundle.json",
                Path(directory) / "signed.json",
            )
            input_path.write_text(json.dumps(SAMPLE))
            result = subprocess.run(
                [sys.executable, "-m", "nockchain", "inspect", str(input_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(
                json.loads(result.stdout)["transactionId"],
                FIXTURE["cases"][0]["response"]["review"]["transactionId"],
            )
            args = [
                "sign",
                str(input_path),
                "--out",
                str(output_path),
                "--key-file",
                str(Path(directory) / "missing-key"),
            ]
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(args), 1)
                self.assertIn("interactive terminal", errors.getvalue())
            with (
                patch("sys.stdin.isatty", return_value=True),
                contextlib.redirect_stderr(io.StringIO()) as errors,
                patch.object(errors, "isatty", return_value=True),
                patch("builtins.input", return_value="no"),
            ):
                self.assertEqual(main(args), 1)
                self.assertIn("declined", errors.getvalue())
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
