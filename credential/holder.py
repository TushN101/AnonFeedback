"""Student-side prover.

Builds a 1-out-of-n OR proof binding the student's secret to a specific
feedback payload and course, and produces a course-scoped nullifier that the
server uses for duplicate detection.
"""

from __future__ import annotations

import hashlib
from typing import List

from zkp import prove
from zkp.group import modexp, nullifier_base_for
from zkp.params import G


def feedback_context(course: str, feedback: str) -> str:
    """Compute the context string bound into the Fiat–Shamir transcript.

    The context includes the course id and a SHA-256 hash of the feedback text.
    Binding the feedback hash means a proof generated for one feedback payload
    cannot be replayed against a different payload — the verifier recomputes
    the challenge using this same context and the challenge will not match.
    """
    if not isinstance(course, str) or not isinstance(feedback, str):
        raise ValueError("course and feedback must be strings")
    fb_hash = hashlib.sha256(feedback.encode("utf-8")).hexdigest()
    return f"feedback:{course}:{fb_hash}"


def build_proof(
    secret: int,
    feedback: str,
    course: str,
    public_set: List[int],
) -> dict:
    """Build a ZKP that the holder of ``secret`` is a member of ``public_set``,
    bound to the given feedback + course, with a course-scoped nullifier.

    Parameters
    ----------
    secret
        The student's secret scalar ``x``.
    feedback
        The feedback text the student is submitting. Bound into the transcript.
    course
        The course id the feedback is for. Bound into the transcript AND used
        to derive the per-course nullifier base ``h = G2^{H(course)}``.
    public_set
        The current public eligible set ``S``. The prover's public key
        ``Y = g^secret`` must be in this list.

    Returns
    -------
    proof dict (see :func:`zkp.prove`). The proof includes a top-level
    ``nullifier`` field (``N = h^secret``) that the server uses for
    duplicate detection — see ``server.routes.api_submit``.

    Raises
    ------
    ValueError
        If the prover's key is not in ``public_set`` (i.e. the student is not
        eligible), or inputs are malformed.
    """
    if not isinstance(secret, int) or secret <= 0:
        raise ValueError("secret must be a positive integer")
    if not isinstance(feedback, str) or not feedback.strip():
        raise ValueError("feedback must be a non-empty string")
    if not isinstance(course, str) or not course.strip():
        raise ValueError("course must be a non-empty string")
    if not isinstance(public_set, list) or not public_set:
        raise ValueError("public_set must be a non-empty list")

    public_key = modexp(G, secret)
    context = feedback_context(course, feedback)
    nullifier_base = nullifier_base_for(course)
    return prove(
        secret=secret,
        public_key=public_key,
        public_set=public_set,
        context=context,
        nullifier_base=nullifier_base,
    )
