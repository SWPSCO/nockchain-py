"""Variable-time Cheetah arithmetic for trusted, offline signing tools."""

from __future__ import annotations
from dataclasses import dataclass

from ._core import PRIME, NockchainError

Field = tuple[int, ...]
ZERO: Field = (0,) * 6
ONE: Field = (1, 0, 0, 0, 0, 0)
ORDER = int("7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf", 16)
_INVERSE_EXPONENT = PRIME**6 - 2


def add(a: Field, b: Field) -> Field:
    return tuple((x + y) % PRIME for x, y in zip(a, b))


def sub(a: Field, b: Field) -> Field:
    return tuple((x - y) % PRIME for x, y in zip(a, b))


def scale(a: Field, value: int) -> Field:
    return tuple(x * value % PRIME for x in a)


def mul(a: Field, b: Field) -> Field:
    result = [0] * 11
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[i + j] += x * y
    for i in range(6, 11):
        result[i - 6] += 7 * result[i]
    return tuple(x % PRIME for x in result[:6])


def square(a: Field) -> Field:
    return mul(a, a)


def inverse(a: Field) -> Field:
    result = ONE
    for bit in bin(_INVERSE_EXPONENT)[2:]:
        result = square(result)
        if bit == "1":
            result = mul(result, a)
    return result


@dataclass(frozen=True, slots=True)
class Point:
    x: Field = ZERO
    y: Field = ZERO
    z: Field = ZERO

    def double(self) -> Point:
        if self.z == ZERO or self.y == ZERO:
            return Point()
        a, b = square(self.x), square(self.y)
        c = square(b)
        d = scale(sub(sub(square(add(self.x, b)), a), c), 2)
        e = add(scale(a, 3), square(square(self.z)))
        x = sub(square(e), scale(d, 2))
        return Point(x, sub(mul(e, sub(d, x)), scale(c, 8)), scale(mul(self.y, self.z), 2))

    def plus(self, q: Point) -> Point:
        if self.z == ZERO:
            return q
        if q.z == ZERO:
            return self
        z1, z2 = square(self.z), square(q.z)
        u1, u2 = mul(self.x, z2), mul(q.x, z1)
        s1, s2 = mul(mul(self.y, q.z), z2), mul(mul(q.y, self.z), z1)
        if u1 == u2:
            return self.double() if s1 == s2 else Point()
        h = sub(u2, u1)
        i = square(scale(h, 2))
        j = mul(h, i)
        r = scale(sub(s2, s1), 2)
        v = mul(u1, i)
        x = sub(sub(square(r), j), scale(v, 2))
        y = sub(mul(r, sub(v, x)), scale(mul(s1, j), 2))
        z = mul(sub(sub(square(add(self.z, q.z)), z1), z2), h)
        return Point(x, y, z)

    def times(self, value: int) -> Point:
        result = Point()
        for bit in bin(value)[2:]:
            result = result.double()
            if bit == "1":
                result = result.plus(self)
        return result

    def affine(self) -> Point:
        if self.z == ZERO or self.z == ONE:
            return self
        z = inverse(self.z)
        z2 = square(z)
        return Point(mul(self.x, z2), mul(mul(self.y, z2), z), ONE)

    def to_bytes(self) -> bytes:
        p = self.affine()
        return b"\x01" + b"".join(x.to_bytes(8, "big") for f in (p.y, p.x) for x in reversed(f))


GENERATOR = Point(
    (
        2754611494552410273,
        8599518745794843693,
        10526511002404673680,
        4830863958577994148,
        375185138577093320,
        12938930721685970739,
    ),
    (
        15384029202802550068,
        2774812795997841935,
        14375303400746062753,
        10708493419890101954,
        13187678623570541764,
        9990732138772505951,
    ),
    ONE,
)


def parse_point(data: bytes) -> Point:
    if len(data) != 97 or data[0] != 1:
        raise NockchainError("invalid Cheetah public key")
    y = tuple(int.from_bytes(data[i : i + 8], "big") for i in range(1, 49, 8))[::-1]
    x = tuple(int.from_bytes(data[i : i + 8], "big") for i in range(49, 97, 8))[::-1]
    if any(v >= PRIME for v in (*x, *y)):
        raise NockchainError("noncanonical Cheetah coordinate")
    p = Point(x, y, ONE)
    if (
        square(y) != add(add(mul(square(x), x), x), (395, 1, 0, 0, 0, 0))
        or p.times(ORDER).z != ZERO
    ):
        raise NockchainError("Cheetah point outside prime-order subgroup")
    return p
