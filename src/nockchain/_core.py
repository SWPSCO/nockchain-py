"""Bounded immutable based nouns, TIP5, and canonical wire encodings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, TypeAlias

from ._constants import LOOKUP, ROUND_CONSTANTS

PRIME = 0xFFFFFFFF00000001
UINT64_MAX = (1 << 64) - 1
MAX_NOUN_NODES = 1 << 20
MAX_JAM_BYTES = 16 << 20
NICKS_PER_NOCK = 1 << 16
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MDS = (
    61402,
    17845,
    26798,
    59689,
    12021,
    40901,
    41351,
    27521,
    56951,
    12034,
    53865,
    43244,
    7454,
    33823,
    28750,
    1108,
)
_R = 0xFFFFFFFF
_R_INV = pow(_R, -1, PRIME)


class NockchainError(ValueError):
    """Invalid, unsupported, or out-of-range protocol input."""


def integer(value: int, maximum: int = UINT64_MAX, label: str = "integer") -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise NockchainError(f"invalid {label}")
    return value


def atom(value: int) -> int:
    """Construct an atom without reducing values outside the Goldilocks field."""
    return integer(value, PRIME - 1, "noun atom")


def _check_node(value: Noun) -> None:
    if not isinstance(value, Cell):
        atom(value)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class Cell:
    """An immutable head/tail pair. Shared children remain immutable."""

    head: Noun
    tail: Noun

    def __post_init__(self) -> None:
        _check_node(self.head)
        _check_node(self.tail)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Cell) and noun_equal(self, other)

    __hash__ = None

    def __repr__(self) -> str:
        return "Cell(<immutable noun>)"


Noun: TypeAlias = int | Cell


def noun_tuple(*values: Noun) -> Noun:
    """Build a right-associated tuple; no values produce atom zero."""
    if not values:
        return 0
    out = values[-1]
    _check_node(out)
    for value in reversed(values[:-1]):
        out = Cell(value, out)
    return out


def noun_list(*values: Noun) -> Noun:
    """Build a zero-terminated Hoon list."""
    return noun_tuple(*values, 0)


def noun_equal(a: Noun, b: Noun) -> bool:
    stack = [(a, b)]
    seen = set()
    while stack:
        a, b = stack.pop()
        if a is b:
            continue
        if isinstance(a, Cell) and isinstance(b, Cell):
            identity = (id(a), id(b))
            if identity in seen:
                continue
            seen.add(identity)
            if len(seen) > MAX_NOUN_NODES:
                raise NockchainError("noun equality exceeds node limit")
            stack.extend(((a.head, b.head), (a.tail, b.tail)))
        elif isinstance(a, Cell) or isinstance(b, Cell) or a != b:
            return False
    return True


def parts(n: Noun, count: int) -> tuple[Noun, ...]:
    out = []
    for _ in range(count - 1):
        if not isinstance(n, Cell):
            raise NockchainError("malformed noun tuple")
        out.append(n.head)
        n = n.tail
    return (*out, n)


def bounded_noun(n: Noun, max_nodes: int = 65536, max_depth: int = 256) -> None:
    stack = [(n, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise NockchainError("noun exceeds inspection limits")
        if isinstance(current, Cell):
            stack.extend(((current.head, depth + 1), (current.tail, depth + 1)))
        else:
            atom(current)


def encode_base58(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\0"))
    value = int.from_bytes(data, "big")
    out = ""
    while value:
        value, rem = divmod(value, 58)
        out = _ALPHABET[rem] + out
    return "1" * zeros + out


def decode_base58(text: str) -> bytes:
    value = 0
    for char in text:
        index = _ALPHABET.find(char)
        if index < 0:
            raise NockchainError("invalid Base58 encoding")
        value = value * 58 + index
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + value.to_bytes((value.bit_length() + 7) // 8, "big")


class Digest(tuple):
    """Five canonical field elements, least significant first; immutable/hashable."""

    __slots__ = ()

    def __new__(cls, limbs: Iterable[int]):
        values = tuple(limbs)
        if len(values) != 5:
            raise NockchainError("a digest has five limbs")
        for value in values:
            atom(value)
        return super().__new__(cls, values)

    def __str__(self) -> str:
        value = sum(limb * PRIME**i for i, limb in enumerate(self))
        return encode_base58(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    def __repr__(self) -> str:
        return f"Digest({tuple.__repr__(self)})"

    def noun(self) -> Noun:
        return noun_tuple(*self)


def parse_digest(text: str) -> Digest:
    if not isinstance(text, str) or not 1 <= len(text) <= 55:
        raise NockchainError("invalid Nockchain digest")
    encoded = decode_base58(text)
    value = int.from_bytes(encoded, "big")
    limbs = []
    for _ in range(5):
        value, rem = divmod(value, PRIME)
        limbs.append(rem)
    result = Digest(limbs)
    if value or str(result) != text:
        raise NockchainError("noncanonical or overflowing digest")
    return result


def noun_digest(n: Noun) -> Digest:
    return Digest(parts(n, 5))


def _permute(state: list[int]) -> None:
    for round_index in range(7):
        values = []
        for i, value in enumerate(state):
            if i < 4:
                value = sum(LOOKUP[(value >> (8 * j)) & 255] << (8 * j) for j in range(8)) % PRIME
            else:
                value = pow(value, 7, PRIME)
            values.append(value)
        state[:] = [
            (
                sum(_MDS[(j - i) % 16] * values[j] for j in range(16))
                + ROUND_CONSTANTS[round_index * 16 + i] * _R
            )
            % PRIME
            for i in range(16)
        ]


def hash_words(words: Iterable[int]) -> Digest:
    """Variable-length TIP5 with replace absorption and canonical field inputs."""
    values = tuple(words)
    for value in values:
        atom(value)
    state = [0] * 16
    offset = 0
    while len(values) - offset >= 10:
        state[:10] = [v * _R % PRIME for v in values[offset : offset + 10]]
        _permute(state)
        offset += 10
    state[:10] = [0] * 10
    tail = values[offset:]
    state[: len(tail)] = [v * _R % PRIME for v in tail]
    state[len(tail)] = _R
    _permute(state)
    return Digest(v * _R_INV % PRIME for v in state[:5])


def hash_cell(a: Digest, b: Digest) -> Digest:
    state = [v * _R % PRIME for v in (*a, *b)] + [_R] * 6
    _permute(state)
    return Digest(v * _R_INV % PRIME for v in state[:5])


def hash_atom(value: int) -> Digest:
    return hash_words((1, value))


def fold_hashes(*values: Digest) -> Digest:
    result = values[-1]
    for value in reversed(values[:-1]):
        result = hash_cell(value, result)
    return result


def hash_noun(noun: Noun, max_nodes: int = MAX_NOUN_NODES) -> Digest:
    """Hash leaf values and shape with a bounded iterative traversal."""
    integer(max_nodes, MAX_NOUN_NODES, "noun node limit")
    if max_nodes == 0:
        raise NockchainError("invalid noun node limit")
    stack = [(noun, False)]
    leaves, shape = [], []
    count = 0
    while stack:
        current, after_head = stack.pop()
        if after_head:
            shape.append(1)
            stack.append((current, False))
            continue
        count += 1
        if count > max_nodes:
            raise NockchainError("noun exceeds logical node limit")
        if isinstance(current, Cell):
            shape.append(0)
            stack.extend(((current.tail, True), (current.head, False)))
        else:
            leaves.append(atom(current))
    return hash_words((len(leaves), *leaves, *shape))


def hash_each(noun: Noun) -> Digest:
    # Only called after bounded_noun on metadata with depth <= 256.
    if isinstance(noun, Cell):
        return hash_cell(hash_each(noun.head), hash_each(noun.tail))
    return hash_atom(noun)


def leaf_count(noun: Noun) -> int:
    stack, count = [noun], 0
    while stack:
        n = stack.pop()
        if isinstance(n, Cell):
            stack.extend((n.head, n.tail))
        else:
            count += 1
    return count


def jam(noun: Noun) -> bytes:
    """Encode literal LSB-first jam, with bounded logical expansion."""
    data = bytearray()
    bit = 0

    def write(value: int, size: int) -> None:
        nonlocal bit
        for i in range(size):
            if bit // 8 == len(data):
                data.append(0)
            data[bit // 8] |= ((value >> i) & 1) << (bit % 8)
            bit += 1

    stack, count = [noun], 0
    while stack:
        n = stack.pop()
        count += 1
        if count > MAX_NOUN_NODES:
            raise NockchainError("noun exceeds logical node limit")
        if isinstance(n, Cell):
            write(1, 2)
            stack.extend((n.tail, n.head))
        else:
            n = atom(n)
            write(0, 1)
            length = n.bit_length()
            if not length:
                write(1, 1)
            else:
                size = length.bit_length()
                write(0, size)
                write(1, 1)
                write(length, size - 1)
                write(n, length)
        if len(data) > MAX_JAM_BYTES:
            raise NockchainError("jam exceeds byte limit")
    return bytes(data)


def cue(data: bytes) -> Noun:
    """Decode jam, rejecting cyclic/forward refs, excess data and expansion bombs."""
    if not isinstance(data, (bytes, bytearray, memoryview)) or not 1 <= len(data) <= MAX_JAM_BYTES:
        raise NockchainError("invalid jam size")
    data = bytes(data)
    bit = 0

    def read(size: int) -> int:
        nonlocal bit
        if not 0 <= size <= 64 or size > len(data) * 8 - bit:
            raise NockchainError("truncated or oversized jam atom")
        value = 0
        for i in range(size):
            value |= ((data[bit // 8] >> (bit % 8)) & 1) << i
            bit += 1
        return value

    def rub() -> int:
        size = 0
        while read(1) == 0:
            size += 1
            if size > 7:
                raise NockchainError("jam atom exceeds field width")
        return 0 if size == 0 else read(read(size - 1) + (1 << (size - 1)))

    refs: dict[int, tuple[Noun, int]] = {}
    stack: list[tuple[int, tuple[Noun, int] | None]] = []
    while True:
        start = bit
        if read(1) == 0:
            current = (atom(rub()), 1)
            refs[start] = current
        elif read(1) == 0:
            if len(stack) >= MAX_NOUN_NODES:
                raise NockchainError("jam exceeds node limit")
            stack.append((start, None))
            continue
        else:
            position = rub()
            if position >= start or position not in refs:
                raise NockchainError("invalid or cyclic jam backreference")
            current = refs[position]
        while stack:
            cell_start, head = stack[-1]
            if head is None:
                stack[-1] = (cell_start, current)
                break
            count = 1 + head[1] + current[1]
            if count > MAX_NOUN_NODES:
                raise NockchainError("jam exceeds logical node limit")
            current = (Cell(head[0], current[0]), count)
            refs[cell_start] = current
            stack.pop()
        if not stack:
            break
    if len(data) * 8 - bit > 7 or read(len(data) * 8 - bit) != 0:
        raise NockchainError("trailing jam data")
    return current[0]


def parse_nocks(text: str) -> int:
    """Parse exact decimal NOCK amounts into whole nicks, without floats."""
    if not isinstance(text, str) or not 1 <= len(text) <= 40:
        raise NockchainError("invalid NOCK amount")
    values = text.split(".")
    if len(values) > 2 or any(not v or not v.isascii() or not v.isdigit() for v in values):
        raise NockchainError("invalid NOCK amount")
    fraction = values[1] if len(values) == 2 else ""
    if len(fraction) > 16:
        raise NockchainError("NOCK decimal precision exceeds 16 places")
    numerator = int("".join(values)) * NICKS_PER_NOCK
    amount, remainder = divmod(numerator, 10 ** len(fraction))
    if remainder:
        raise NockchainError("NOCK amount has sub-nick precision")
    return integer(amount, UINT64_MAX, "NOCK amount")


def format_nocks(nicks: int) -> str:
    integer(nicks)
    whole, remainder = divmod(nicks, NICKS_PER_NOCK)
    if not remainder:
        return str(whole)
    return f"{whole}.{remainder * 152587890625:016d}".rstrip("0")
