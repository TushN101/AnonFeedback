"""CDS 1-out-of-n OR proof of set membership, with a course-scoped nullifier.

This is the Cramer–Damgård–Schoenmakers disjunctive Sigma-protocol, made
non-interactive via the Fiat–Shamir heuristic. We extend the basic
construction with a **Chaum–Pedersen** equality proof that ties a published
nullifier ``N`` to the same secret ``x`` whose knowledge is proved by the OR
proof — so that the nullifier cannot be forged independently and the server
can safely use it for duplicate detection.

Statement proved
----------------
Given a public set ``S = {Y_1, ..., Y_n}`` of elements of the order-``q``
subgroup of ``Z_P^*`` and a public nullifier base ``h``:

    "I know an integer ``x`` such that ``g^x == Y_j`` for *some* ``j`` —
     but I do not reveal which ``j`` — and ``N == h^x`` for the *same* ``x``."

The published proof reveals ``N``. ``N`` is deterministic in
``(x_k, h)``, where ``h`` is derived from the course id, so:

* Same student + same course → same ``N`` (duplicate detection works).
* Same student + different course → different ``h`` → unlinkable ``N`` (DDH).
* Different students + same course → different ``x`` → different ``N``.

The server cannot test ``N`` against each ``Y_j`` to recover ``j``: that
would require knowing ``log_g(h)``, which is unknown because ``h = G2^t``
for a nothing-up-my-sleeve generator ``G2`` whose discrete log with respect
to ``G`` is unknown (see ``zkp.group.G2`` and ``hash_to_subgroup``).

Construction (sketch)
---------------------
For the real index ``k`` (the prover's own key):

* ``N = h^{x_k}``
* pick ``r_k ←$ Z_q``; ``R_k = g^{r_k}``, ``M_k = h^{r_k}``.

For every other index ``j ≠ k`` (simulated):

* pick ``c_j, s_j ←$ Z_q``; ``R_j = g^{s_j} · Y_j^{-c_j}``,
  ``M_j = h^{s_j} · N^{-c_j}``.

Combine via Fiat–Shamir:

* ``c = H(domain ‖ N ‖ h ‖ R_1 ‖ M_1 ‖ ... ‖ R_n ‖ M_n ‖ S ‖ context)``
* ``c_k = c − Σ_{j≠k} c_j  mod q``
* ``s_k = r_k + c_k · x_k  mod q``

Verification
------------
* Recompute ``c`` from the transcript; check it equals the published challenge.
* Check ``Σ_j c_j ≡ c  mod q``.
* For every ``j``: check ``g^{s_j} ≡ R_j · Y_j^{c_j}  mod p`` AND
  ``h^{s_j} ≡ M_j · N^{c_j}  mod p``.

If all checks pass, the verifier is convinced that the prover knew a single
``x`` such that ``g^x`` is some ``Y_j ∈ S`` and ``h^x = N``. The transcript
is statistically independent of ``k``, so the proof reveals nothing about
which ``Y_j`` is the prover's — only ``N`` is revealed, which is the
intended pseudonym for duplicate detection.

Properties (under the assumptions in ``plan.md`` §5)
----------------------------------------------------
* **Completeness** — probability 1 for an honest prover.
* **Soundness** — extraction succeeds with probability ``1 − 2^{-λ}`` for a
  256-bit hash; relies on DL hardness and the random-oracle model.
* **Zero-knowledge / unlinkability of the transcript** — the transcript is
  simulatable without ``x_k``; the distribution is independent of ``k``.
* **Nullifier soundness** — a malicious prover cannot produce a valid proof
  with a ``N`` that was not derived from their actual ``x_k`` for the given
  ``h`` (the Chaum–Pedersen check enforces this). Therefore the server's
  duplicate detection cannot be bypassed by lying about ``N``.

This is an *educational* implementation. It has not been formally verified.
See ``plan.md`` §5.3 for limitations.
"""

from __future__ import annotations

from typing import List

from .group import (
    deserialize_proof,
    hash_to_scalar,
    in_subgroup,
    modexp,
    rand_scalar,
    serialize_proof,
)
from .params import G, P, Q


class ProofValidationError(Exception):
    """Raised when a proof fails verification.

    The ``reason`` attribute carries a short, *non-revealing* description of
    the failure category (e.g. ``"malformed"``). We deliberately do NOT expose
    which component failed, to avoid leaking signal about the prover.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- public API --------------------------------------------------------------


def prove(
    secret: int,
    public_key: int,
    public_set: List[int],
    context: bytes | str,
    nullifier_base: int,
) -> dict:
    """Build a 1-out-of-n OR proof with a bound nullifier.

    Parameters
    ----------
    secret
        The prover's secret scalar ``x`` in ``[1, Q-1]``.
    public_key
        ``Y = g^x``. Must be an element of ``public_set``.
    public_set
        The ordered list ``S = [Y_1, ..., Y_n]`` of all eligible public keys.
    context
        A binding string (typically the ``feedback_context`` from
        :mod:`credential.holder`) tying this proof to a specific feedback
        payload.
    nullifier_base
        The per-course base ``h = G2^{t_course}`` (see
        :func:`zkp.group.nullifier_base_for`). The published nullifier is
        ``N = h^{x}``.

    Returns
    -------
    dict with ``challenge``, ``nullifier``, and ``components`` (each
    ``{R, M, c, s}``). Use :func:`zkp.group.serialize_proof` to ship as JSON.

    Raises
    ------
    ValueError
        If the prover's ``public_key`` is not in ``public_set`` (i.e. the
        student is not eligible), or inputs are malformed.
    """
    if not isinstance(secret, int) or not (1 <= secret < Q):
        raise ValueError("secret out of range")
    if not in_subgroup(public_key):
        raise ValueError("public_key is not in the subgroup")
    if not in_subgroup(nullifier_base):
        raise ValueError("nullifier_base is not in the subgroup")
    if not public_set:
        raise ValueError("public_set is empty")

    # Locate the prover's index. (Prover-side only; the verifier never does
    # this step.)
    try:
        k = public_set.index(public_key)
    except ValueError as exc:
        raise ValueError("public_key is not in public_set") from exc

    n = len(public_set)
    components = [None] * n  # type: list[dict | None]
    c_sim_sum = 0

    # Nullifier: N = h^{x_k}. Published alongside the proof.
    N = modexp(nullifier_base, secret)

    # Simulated components (j != k).
    for j in range(n):
        if j == k:
            continue
        c_j = rand_scalar()
        s_j = rand_scalar()
        # R_j = g^{s_j} * Y_j^{-c_j} mod p
        Yj = public_set[j]
        Yj_inv_cj = pow(pow(Yj, -1, P), c_j, P)
        R_j = (modexp(G, s_j) * Yj_inv_cj) % P
        # M_j = h^{s_j} * N^{-c_j} mod p
        N_inv_cj = pow(pow(N, -1, P), c_j, P)
        M_j = (modexp(nullifier_base, s_j) * N_inv_cj) % P
        components[j] = {"R": R_j, "M": M_j, "c": c_j, "s": s_j}
        c_sim_sum = (c_sim_sum + c_j) % Q

    # Real component (k).
    r_k = rand_scalar()
    R_k = modexp(G, r_k)
    M_k = modexp(nullifier_base, r_k)
    components[k] = {"R": R_k, "M": M_k, "c": None, "s": None}  # filled below

    # Fiat–Shamir challenge over the full transcript (including N and h).
    R_list = [components[j]["R"] for j in range(n)]
    M_list = [components[j]["M"] for j in range(n)]
    c = _transcript_challenge(N, nullifier_base, R_list, M_list, public_set, context)

    # Solve for c_k and s_k.
    c_k = (c - c_sim_sum) % Q
    s_k = (r_k + c_k * secret) % Q
    components[k]["c"] = c_k
    components[k]["s"] = s_k

    return {"challenge": c, "nullifier": N, "components": components}


def verify(
    proof: dict,
    public_set: List[int],
    context: bytes | str,
    nullifier_base: int,
) -> bool:
    """Verify a 1-out-of-n OR proof with nullifier against ``public_set`` and
    ``context``.

    Returns ``True`` iff the proof is valid. Raises
    :class:`ProofValidationError` with a non-revealing ``reason`` if the proof
    is malformed or fails any check.

    The verifier does NOT learn which component was the "real" one. The
    published ``N`` is the only thing that can be used for duplicate
    detection — and it is unlinkable across courses / students.
    """
    if not isinstance(proof, dict):
        raise ProofValidationError("malformed")
    for field in ("challenge", "components", "nullifier"):
        if field not in proof:
            raise ProofValidationError("malformed")
    components = proof["components"]
    challenge = proof["challenge"]
    nullifier = proof["nullifier"]
    if not isinstance(components, list):
        raise ProofValidationError("malformed")
    if len(components) != len(public_set):
        raise ProofValidationError("length-mismatch")
    if len(components) == 0:
        raise ProofValidationError("empty-set")
    if not in_subgroup(nullifier_base):
        raise ProofValidationError("bad-base")
    if not in_subgroup(nullifier):
        raise ProofValidationError("bad-nullifier")

    # Validate every public-set element is in the subgroup, to prevent an
    # adversary from injecting small-subgroup elements that could leak info.
    for Y in public_set:
        if not in_subgroup(Y):
            raise ProofValidationError("bad-set")

    # Validate component structure and ranges.
    for comp in components:
        if not isinstance(comp, dict) or not {"R", "M", "c", "s"}.issubset(comp):
            raise ProofValidationError("malformed")
        R = comp["R"]
        M = comp["M"]
        c_j = comp["c"]
        s_j = comp["s"]
        if not (isinstance(R, int) and isinstance(M, int)
                and isinstance(c_j, int) and isinstance(s_j, int)):
            raise ProofValidationError("malformed")
        if not (0 <= c_j < Q and 0 <= s_j < Q):
            raise ProofValidationError("range")
        if not in_subgroup(R):
            raise ProofValidationError("bad-element")
        if not in_subgroup(M):
            raise ProofValidationError("bad-element")

    # Re-derive the Fiat–Shamir challenge from the published R, M values.
    R_list = [comp["R"] for comp in components]
    M_list = [comp["M"] for comp in components]
    expected_challenge = _transcript_challenge(
        nullifier, nullifier_base, R_list, M_list, public_set, context
    )
    if expected_challenge != challenge:
        raise ProofValidationError("challenge-mismatch")

    # Check that the per-component challenges sum to the published challenge.
    c_sum = 0
    for comp in components:
        c_sum = (c_sum + comp["c"]) % Q
    if c_sum != challenge:
        raise ProofValidationError("challenge-sum")

    # Check each component's pair of Schnorr equations:
    #   g^{s_j} == R_j * Y_j^{c_j}    mod p
    #   h^{s_j} == M_j * N^{c_j}      mod p
    for comp, Y in zip(components, public_set):
        R = comp["R"]
        M = comp["M"]
        c_j = comp["c"]
        s_j = comp["s"]
        lhs1 = modexp(G, s_j)
        rhs1 = (R * modexp(Y, c_j)) % P
        if lhs1 != rhs1:
            raise ProofValidationError("equation")
        lhs2 = modexp(nullifier_base, s_j)
        rhs2 = (M * modexp(nullifier, c_j)) % P
        if lhs2 != rhs2:
            raise ProofValidationError("equation")

    return True


# --- internals ---------------------------------------------------------------


def _transcript_challenge(
    nullifier: int,
    nullifier_base: int,
    R_list: List[int],
    M_list: List[int],
    public_set: List[int],
    context,
) -> int:
    """Fiat–Shamir challenge over the transcript.

    The transcript includes the nullifier N, the nullifier base h, every
    (R_j, M_j) pair, the public set S, and the context. Including N and h
    prevents a malicious prover from swapping in a different nullifier after
    generating the proof.
    """
    h_inputs = [
        "or-proof-with-nullifier",
        "nullifier", nullifier,
        "base", nullifier_base,
        "n", len(R_list),
    ]
    for R, M in zip(R_list, M_list):
        h_inputs.append("R"); h_inputs.append(R)
        h_inputs.append("M"); h_inputs.append(M)
    h_inputs.append("set")
    h_inputs.append(len(public_set))
    for Y in public_set:
        h_inputs.append(Y)
    h_inputs.append("context")
    h_inputs.append(context)
    return hash_to_scalar(*h_inputs)


# Re-export serialisation helpers for convenience.
__all__ = [
    "prove",
    "verify",
    "ProofValidationError",
    "serialize_proof",
    "deserialize_proof",
]
