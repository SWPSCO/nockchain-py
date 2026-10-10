import json
from functools import lru_cache
from pathlib import Path
import unittest

import nockchain as n

DATA = Path(__file__).resolve().parents[1] / "testdata"
REFERENCE = json.loads((DATA / "reference.json").read_text())


@lru_cache(maxsize=64)
def key_for(seed, path):
    key = n.master(bytes.fromhex(seed))
    for index in path:
        key = key.child(index)
    return key


def make_noun(value):
    if isinstance(value, list):
        return n.Cell(make_noun(value[0]), make_noun(value[1]))
    return n.atom(value)


class ProtocolTests(unittest.TestCase):
    def test_tip5(self):
        for v in REFERENCE["hashes"]:
            self.assertEqual(n.hash_words(v["words"]), n.Digest(v["digest"]))
        for bad in (-1, n.PRIME, True, 1.0):
            with self.assertRaises(n.NockchainError):
                n.hash_words([bad])

    def test_nouns(self):
        for v in REFERENCE["nouns"]:
            noun = make_noun(v["noun"])
            self.assertEqual(n.hash_noun(noun), n.Digest(v["digest"]))
            self.assertEqual(n.jam(noun).hex(), v["jam"])
            self.assertTrue(n.noun_equal(noun, n.cue(bytes.fromhex(v["jam"]))))
        deep = 0
        for _ in range(2000):
            deep = n.Cell(0, deep)
        self.assertTrue(n.noun_equal(deep, n.cue(n.jam(deep))))
        shared = 0
        for _ in range(25):
            shared = n.Cell(shared, shared)
        with self.assertRaises(n.NockchainError):
            n.hash_noun(shared, 100)
        for data in (b"", b"\0", b"\xff", b"\x02\0", b"\x82"):
            with self.assertRaises(n.NockchainError):
                n.cue(data)
        with self.assertRaises(AttributeError):
            n.Cell(0, 0).head = 1

    def test_wallet_vectors(self):
        for v in REFERENCE["keys"]:
            with self.subTest(path=v["path"], seed=v["seed"][:4]):
                key = key_for(v["seed"], tuple(v["path"]))
                self.assertEqual(key.zpub(), v["zpub"])
                self.assertEqual(key.zprv(), v["zprv"])
                self.assertEqual(key.public_bytes().hex(), v["public"])
                self.assertEqual(key.address(), v["address"])
                self.assertEqual(key.lock_address(), v["lock"])
                self.assertEqual(n.parse_extended_key(v["zprv"]).zpub(), v["zpub"])
                public = n.parse_public_key(v["zpub"])
                self.assertFalse(public.is_private)
                self.assertEqual(public.child(7).zpub(), key.child(7).public().zpub())
                with self.assertRaises(n.NockchainError):
                    n.parse_public_key(v["zprv"])
                with self.assertRaises(n.NockchainError):
                    public.child(1 << 31)
                self.assertEqual(str(n.parse_digest(v["address"])), v["address"])
                self.assertNotIn(v["secret"], repr(key))
                self.assertNotIn(v["zprv"], str(key))
        key = key_for(REFERENCE["keys"][0]["seed"], ())
        for path in ("x/0", "m/", "m/01", "m/-1", "m/+1", "m/2147483648", "m/1h"):
            with self.assertRaises(n.NockchainError):
                key.derive(path)
        self.assertEqual(key.derive("m/0'/7").zprv(), key.child(1 << 31).child(7).zprv())
        with self.assertRaises(AttributeError):
            key._secret = bytes(32)

    def test_signatures(self):
        for v in REFERENCE["signatures"]:
            key = key_for(v["seed"], tuple(v["path"]))
            message = n.Digest(v["message"])
            signature = key.sign_digest(message)
            self.assertEqual(signature.challenge, tuple(v["challenge"]))
            self.assertEqual(signature.response, tuple(v["response"]))
            self.assertTrue(n.verify_digest(key.public_bytes(), message, signature))
        invalid = n.Signature((0,) * 8, (0,) * 8)
        self.assertFalse(n.verify_digest(key.public_bytes(), message, invalid))
        self.assertFalse(n.verify_digest(bytes(97), message, signature))
        self.assertFalse(n.verify_digest(key.public_bytes(), n.Digest([9, 8, 7, 6, 5]), signature))

    def test_bip39(self):
        for entropy, phrase, seed, _ in json.loads((DATA / "bip39.json").read_text()):
            recovery = n.mnemonic_from_entropy(bytes.fromhex(entropy))
            self.assertEqual(recovery.words(), phrase)
            self.assertNotIn(phrase, repr(recovery))
            derived = n.seed_from_mnemonic(phrase, "TREZOR")
            self.assertEqual(derived.to_bytes().hex(), seed)
            self.assertNotIn(seed, repr(derived))
        phrase = n.generate_mnemonic().words()
        self.assertEqual(len(phrase.split()), 24)
        self.assertEqual(n.seed_from_mnemonic(phrase, "é"), n.seed_from_mnemonic(phrase, "e\u0301"))
        with self.assertRaises(n.NockchainError):
            n.seed_from_mnemonic("abandon " * 12)

    def test_amounts(self):
        for value in (0, 1, 65535, 65536, (1 << 53) + 1, (1 << 64) - 1):
            self.assertEqual(n.parse_nocks(n.format_nocks(value)), value)
        for value in (
            "",
            "-1",
            "+1",
            "1e3",
            " 1",
            "1.",
            ".5",
            "0.1",
            "0.00000000000000001",
            "281474976710656",
        ):
            with self.assertRaises(n.NockchainError):
                n.parse_nocks(value)


if __name__ == "__main__":
    unittest.main()
