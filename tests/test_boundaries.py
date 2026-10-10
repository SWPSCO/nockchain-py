"""Adversarial wire inputs and key-validation boundaries."""

import hashlib
import unittest

import nockchain as n
from nockchain._core import decode_base58, encode_base58
from test_protocol import REFERENCE, key_for


def shared_jam(depth):
    data, bit = bytearray(), 0

    def write(value, size):
        nonlocal bit
        for i in range(size):
            if bit // 8 == len(data):
                data.append(0)
            data[bit // 8] |= ((value >> i) & 1) << (bit % 8)
            bit += 1

    def mat(value):
        length = value.bit_length()
        if not length:
            write(1, 1)
            return
        size = length.bit_length()
        write(0, size)
        write(1, 1)
        write(length, size - 1)
        write(value, length)

    def emit(level):
        if level == 0:
            write(0, 1)
            mat(1)
        else:
            write(1, 2)
            position = bit
            emit(level - 1)
            write(3, 2)
            mat(position)

    emit(depth)
    return bytes(data)


class BoundaryTests(unittest.TestCase):
    def test_shared_backreferences_and_expansion_limit(self):
        noun = n.cue(shared_jam(5))
        self.assertIs(noun.head, noun.tail)
        self.assertEqual(n.hash_noun(noun), n.hash_noun(n.cue(n.jam(noun))))
        with self.assertRaises(n.NockchainError):
            n.cue(shared_jam(21))
        a, b = 0, 0
        for _ in range(60):
            a, b = n.Cell(a, a), n.Cell(b, b)
        self.assertTrue(n.noun_equal(a, b))

    def test_keys_reject_invalid_fields_with_valid_checksums(self):
        key = key_for(REFERENCE["keys"][0]["seed"], ())
        payload = decode_base58(key.zpub())[:-4]
        mutations = [
            (4, b"\0"),
            (0, bytes([payload[0] ^ 1])),
            (46, b"\0"),
            (47, n.PRIME.to_bytes(8, "big")),
            (60, bytes([payload[60] ^ 1])),
            (10, b"\1"),
        ]
        for offset, replacement in mutations:
            changed = bytearray(payload)
            changed[offset : offset + len(replacement)] = replacement
            checksum = hashlib.sha256(hashlib.sha256(changed).digest()).digest()[:4]
            with self.assertRaises(n.NockchainError):
                n.parse_extended_key(encode_base58(bytes(changed) + checksum))
        for value in ("", "1111", "0", "z" * 56):
            with self.assertRaises(n.NockchainError):
                n.parse_digest(value)

    def test_policy_ranges_and_copies(self):
        key = key_for(REFERENCE["keys"][0]["seed"], ())
        pkh = n.parse_digest(key.address())
        keys = [pkh]
        lock = n.LockV1(1, keys)
        keys[0] = n.Digest([0] * 5)
        self.assertEqual(lock.keys[0], pkh)
        for threshold, values in ((0, [pkh]), (2, [pkh]), (1, [pkh, pkh]), (True, [pkh])):
            with self.assertRaises(n.NockchainError):
                n.LockV1(threshold, values)
        for low, high in ((10, 9), (-1, None), (None, n.PRIME)):
            with self.assertRaises(n.NockchainError):
                n.HeightRange(low, high)
