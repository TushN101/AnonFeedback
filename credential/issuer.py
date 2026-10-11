"""College-side credential issuance and eligible-set management.

The issuer holds two pieces of state:

* ``eligible_set`` — the public, ordered list ``S = [Y_1, ..., Y_n]`` of all
  eligible student public keys. This list is *public*; it is what the verifier
  uses to check proofs.
* ``issuance_log`` — a private, in-memory log of which (synthetic) student name
  was issued which public key. **This log is consulted only at issuance time
  for the admin UI, never during proof verification.** Theunlinkability
  property of the protocol holds *because the verification path does not read
  this log*. See ``plan.md`` §3.2 and §5.2 A3.

The issuer does **not** persist student secrets. After ``issue()`` returns the
secret to the caller, the issuer forgets it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from zkp.group import modexp, rand_scalar
from zkp.params import G


@dataclass
class IssueResult:
    """The bundle returned to the admin when a credential is issued.

    The admin is expected to forward ``secret`` to the student over an
    out-of-band channel and then discard it. The issuer does not retain
    ``secret``.
    """

    student_id: str
    name: str
    secret: int
    public_key: int

    def as_dict(self) -> dict:
        return {
            "student_id": self.student_id,
            "name": self.name,
            "secret": str(self.secret),
            "public_key": str(self.public_key),
        }


@dataclass
class Issuer:
    """In-memory college credential issuer.

    A single instance is shared across the Flask app (see ``server/store.py``).
    """

    # The public eligible set. Order matters: proofs are bound to a specific
    # (ordered) set, so reordering or removing elements invalidates in-flight
    # proofs.
    eligible_set: List[int] = field(default_factory=list)

    # name -> (student_id, public_key). Private; never used during verification.
    issuance_log: Dict[str, Tuple[str, int]] = field(default_factory=dict)

    # student_id -> name, for the admin UI to render the table.
    id_to_name: Dict[str, str] = field(default_factory=dict)

    # Courses the college offers. Just string labels for the demo.
    courses: List[str] = field(default_factory=list)

    def issue(self, name: str) -> IssueResult:
        """Issue a credential for a named student.

        Generates a fresh secret ``x``, computes ``Y = g^x``, adds ``Y`` to
        ``eligible_set``, and returns the bundle. The secret is **not**
        retained by the issuer.

        Raises ``ValueError`` if ``name`` is empty or already issued.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("student name must be a non-empty string")
        name = name.strip()
        if name in self.issuance_log:
            raise ValueError(f"a credential has already been issued for '{name}'")
        secret = rand_scalar()
        public_key = modexp(G, secret)
        student_id = uuid.uuid4().hex[:12]
        self.eligible_set.append(public_key)
        self.issuance_log[name] = (student_id, public_key)
        self.id_to_name[student_id] = name
        return IssueResult(
            student_id=student_id,
            name=name,
            secret=secret,
            public_key=public_key,
        )

    def add_course(self, course: str) -> None:
        if not isinstance(course, str) or not course.strip():
            raise ValueError("course must be a non-empty string")
        course = course.strip()
        if course not in self.courses:
            self.courses.append(course)

    def eligible_size(self) -> int:
        return len(self.eligible_set)

    def get_name_for(self, student_id: str) -> Optional[str]:
        return self.id_to_name.get(student_id)

    def public_set_view(self) -> List[str]:
        """JSON-friendly view of the eligible set (strings)."""
        return [str(y) for y in self.eligible_set]
