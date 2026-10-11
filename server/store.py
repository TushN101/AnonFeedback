"""In-memory store for the AnonFeedback demo.

This module owns the single shared :class:`credential.Issuer` instance and the
list of submitted feedback records. All state is in-memory and lost on restart
— appropriate for a demo, and a deliberate choice so that no student secret
ever touches disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List

from credential import Issuer


@dataclass
class FeedbackRecord:
    """A single submitted feedback record, as stored after verification.

    Note: this record deliberately contains NO student identifier. The
    ``proof`` field is the public ZKP transcript; the ``feedback`` and
    ``course`` fields are what the student chose to submit. The ``verified``
    flag is always True for stored records (we reject before storing).

    The ``nullifier`` field is the course-scoped pseudonym ``N = h^{x_k}``
    bound into the proof (see ``zkp.or_proof``). It is stored so the server
    can reject duplicate submissions for the same (student, course) pair,
    but it is NOT exposed in the public ``as_dict`` view — only the admin
    sees it (for debugging) via ``admin_dict``.
    """

    feedback: str
    course: str
    proof: dict          # serialised proof (challenge + nullifier + components)
    nullifier: int       # N = h^{x_k}, course-scoped; used for dedup
    timestamp: float     # seconds since epoch (set by the server)
    verified: bool = True

    def as_dict(self) -> dict:
        """Public view of feedback (no proof internals, no identity, no nullifier)."""
        return {
            "feedback": self.feedback,
            "course": self.course,
            "timestamp": self.timestamp,
            "verified": self.verified,
            # We do NOT expose the full proof in the public board view, and
            # we do NOT expose the nullifier (it's a stable per-course
            # pseudonym; publishing it would let observers count which
            # submissions came from the same nullifier — by design there is
            # at most one per course, but exposing it is unnecessary).
            "proof_components": len(self.proof["components"]),
        }

    def admin_dict(self) -> dict:
        """Admin view of feedback. Same as public view, plus the nullifier
        (for debugging / audit). The nullifier is NOT a student identifier:
        it is unlinkable across courses and across students."""
        d = self.as_dict()
        d["nullifier"] = str(self.nullifier)
        return d


class Store:
    """Process-wide singleton holding demo state."""

    def __init__(self):
        self.issuer = Issuer()
        self.feedback: List[FeedbackRecord] = []

    def add_feedback(self, record: FeedbackRecord) -> None:
        self.feedback.append(record)

    def has_nullifier(self, nullifier: int) -> bool:
        """Return True iff a feedback with the given nullifier is already stored.

        Because the nullifier is deterministic in (student_secret, course),
        this returns True iff the same student has already submitted for the
        same course.
        """
        return any(r.nullifier == nullifier for r in self.feedback)

    def feedback_view(self) -> List[dict]:
        """Public view of feedback (no proof internals, no identity)."""
        return [r.as_dict() for r in self.feedback]

    def admin_feedback_view(self) -> List[dict]:
        """Admin view of feedback (includes nullifier for audit)."""
        return [r.admin_dict() for r in self.feedback]


# Module-level singleton. Flask routes import this directly.
_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store()
    return _store


def reset_store() -> Store:
    """Replace the singleton with a fresh one. Used by tests."""
    global _store
    _store = Store()
    return _store
