"""Group arithmetic helpers for the AnonFeedback ZKP.

Everything here operates on the prime-order subgroup of order ``Q`` inside
``Z_P^*`` (see :mod:`zkp.params`). These helpers are deliberately small and
auditable.
"""

from __future__ import annotations

import hashlib
import secrets

from .params import DOMAIN, G, P, Q


def rand_scalar() -> int:
    """Return a uniformly random integer in ``[1, Q-1]``."""
    # secrets.randbelow returns [0, n); add 1 to avoid 0 (which would be a
    # degenerate secret).
    return secrets.randbelow(Q - 1) + 1


def modexp(base: int, exp: int) -> int:
    """Modular exponentiation ``base**exp mod P`` using Python's native
    ``pow`` (which uses an efficient C implementation)."""
    return pow(base, exp, P)


def hash_to_scalar(*fields: bytes | str | int) -> int:
    """Hash an ordered list of fields to a scalar in ``[0, Q-1]``.

    The encoding is unambiguous: each field is length-prefixed with its byte
    length as a 64-bit unsigned big-endian integer, and a domain-separation
    tag is prepended. This prevents cross-protocol and cross-field
    concatenation ambiguity in the Fiat–Shamir transcript.
    """
    h = hashlib.sha256()
    h.update(_encode_field(DOMAIN))
    for f in fields:
        h.update(_encode_field(f))
    digest = h.digest()
    # Reduce 256-bit digest mod Q. The bias here is at most 2^{-128} or so
    # (since Q is ~2^{1023}), which is cryptographically negligible.
    return int.from_bytes(digest, "big") % Q


def hash_to_subgroup(label: str) -> int:
    """Derive a subgroup element from a string label using a
    nothing-up-my-sleeve hash.

    The result is in the order-``Q`` subgroup of ``Z_P^*`` (we square a hash
    output to land in the quadratic residues). Because the derivation is
    deterministic and public, *no one* knows the discrete logarithm of the
    result with respect to ``G`` (under the random-oracle assumption on
    SHA-256). This is the property we need for the second generator ``G2``
    used in the nullifier: the server cannot compute ``log_G(G2)`` and so
    cannot test a published nullifier ``N = G2^{x_k}`` against each eligible
    public key ``Y_j = G^{x_j}`` to recover the student's index.
    """
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty string")
    i = 0
    while True:
        h = hashlib.sha256(f"{DOMAIN}.{label}.{i}".encode("utf-8")).digest()
        x = int.from_bytes(h, "big") % P
        if x < 2:
            i += 1
            continue
        # Square to land in the quadratic-residue subgroup (order Q).
        cand = (x * x) % P
        if cand != 1 and modexp(cand, Q) == 1:
            return cand
        i += 1


# Second independent generator. Computed once at import time. Its discrete
# log with respect to G is unknown (see hash_to_subgroup above). Used to
# build the course-scoped nullifier base G2^t_course for duplicate-prevention.
G2 = hash_to_subgroup("second-generator")


def nullifier_base_for(course: str) -> int:
    """Compute the per-course nullifier base ``h = G2^{t_course} mod P``.

    ``t_course = H("nullifier" ‖ course)`` is a publicly computable scalar
    derived from the course id. The nullifier base ``h`` is also public.

    The nullifier itself is ``N = h^{x_k} mod P`` where ``x_k`` is the
    student's secret. Because the server cannot compute ``log_G(h)``, it
    cannot test ``N`` against each eligible ``Y_j = G^{x_j}``.

    For the same student and the same course, ``N`` is deterministic —
    enabling duplicate detection. For the same student and different courses,
    ``h`` differs and ``N`` is unlinkable (DDH). For different students and
    the same course, ``N`` differs and is unlinkable.
    """
    if not isinstance(course, str) or not course.strip():
        raise ValueError("course must be a non-empty string")
    t = hash_to_scalar("nullifier", course)
    return modexp(G2, t)


def _encode_field(f) -> bytes:
    """Length-prefixed encoding of a single transcript field."""
    if isinstance(f, str):
        b = f.encode("utf-8")
    elif isinstance(f, int):
        # Minimum-length big-endian encoding. 0 encodes as a single zero byte
        # so that "0" and "" are distinguishable.
        b = f.to_bytes((f.bit_length() + 7) // 8 or 1, "big")
    elif isinstance(f, (bytes, bytearray)):
        b = bytes(f)
    else:
        raise TypeError(f"Unsupported transcript field type: {type(f)!r}")
    # 64-bit length prefix.
    return len(b).to_bytes(8, "big") + b


def in_subgroup(y: int) -> bool:
    """Return True iff ``y`` is a valid element of the order-``Q`` subgroup:
    integer in ``[2, P-2]`` and ``y**Q == 1 mod P``."""
    if not isinstance(y, int):
        return False
    if y < 2 or y >= P - 1:
        return False
    return modexp(y, Q) == 1


def serialize_proof(proof: dict) -> dict:
    """Return a JSON-serialisable view of a proof dict (everything to ``str``).

    The proof now carries a top-level ``nullifier`` (the published course-
    scoped pseudonym used for duplicate detection) and each component carries
    an additional ``M`` commitment (the Chaum-Pedersen commitment that ties
    the nullifier to the same secret `x` proved by the `R` commitment).
    """
    return {
        "challenge": str(proof["challenge"]),
        "nullifier": str(proof["nullifier"]),
        "components": [
            {"R": str(c["R"]), "M": str(c["M"]), "c": str(c["c"]), "s": str(c["s"])}
            for c in proof["components"]
        ],
    }


def deserialize_proof(data: dict) -> dict:
    """Inverse of :func:`serialize_proof`. Raises ``ValueError`` on malformed input."""
    if not isinstance(data, dict):
        raise ValueError("proof must be a JSON object")
    if "challenge" not in data or "components" not in data or "nullifier" not in data:
        raise ValueError("proof missing 'challenge', 'nullifier', or 'components'")
    try:
        challenge = int(data["challenge"])
    except (TypeError, ValueError):
        raise ValueError("proof 'challenge' is not an integer")
    try:
        nullifier = int(data["nullifier"])
    except (TypeError, ValueError):
        raise ValueError("proof 'nullifier' is not an integer")
    comps_in = data["components"]
    if not isinstance(comps_in, list) or len(comps_in) == 0:
        raise ValueError("proof 'components' must be a non-empty list")
    components = []
    for i, c in enumerate(comps_in):
        if not isinstance(c, dict) or not {"R", "M", "c", "s"}.issubset(c):
            raise ValueError(f"proof component {i} malformed")
        try:
            R = int(c["R"])
            M = int(c["M"])
            cc = int(c["c"])
            s = int(c["s"])
        except (TypeError, ValueError):
            raise ValueError(f"proof component {i} has non-integer fields")
        components.append({"R": R, "M": M, "c": cc, "s": s})
    return {"challenge": challenge, "nullifier": nullifier, "components": components}
