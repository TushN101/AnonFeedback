"""Tests for the credential layer (issuer + holder)."""

import pytest

from credential import Issuer, build_proof, feedback_context
from zkp import ProofValidationError, verify
from zkp.group import modexp, nullifier_base_for
from zkp.params import G


class TestIssuer:
    def test_issue_adds_to_eligible_set(self):
        iss = Issuer()
        assert iss.eligible_size() == 0
        r = iss.issue("Alice")
        assert iss.eligible_size() == 1
        assert r.name == "Alice"
        assert r.secret > 0
        assert r.public_key == modexp(G, r.secret)
        assert r.public_key in iss.eligible_set

    def test_issue_rejects_empty_name(self):
        iss = Issuer()
        with pytest.raises(ValueError):
            iss.issue("")
        with pytest.raises(ValueError):
            iss.issue("   ")
        with pytest.raises(ValueError):
            iss.issue(None)  # type: ignore[arg-type]

    def test_issue_rejects_duplicate_name(self):
        iss = Issuer()
        iss.issue("Alice")
        with pytest.raises(ValueError):
            iss.issue("Alice")

    def test_issue_trims_whitespace(self):
        iss = Issuer()
        r = iss.issue("  Alice  ")
        assert r.name == "Alice"

    def test_add_course_idempotent(self):
        iss = Issuer()
        iss.add_course("DBMS")
        iss.add_course("DBMS")
        iss.add_course("  OS  ")
        assert iss.courses == ["DBMS", "OS"]

    def test_add_course_rejects_empty(self):
        iss = Issuer()
        with pytest.raises(ValueError):
            iss.add_course("")

    def test_get_name_for(self):
        iss = Issuer()
        r = iss.issue("Alice")
        assert iss.get_name_for(r.student_id) == "Alice"
        assert iss.get_name_for("nonexistent") is None


class TestHolder:
    def test_build_proof_round_trip(self):
        iss = Issuer()
        for name in ["A", "B", "C", "D"]:
            iss.issue(name)
        a = iss.issue("Alice-too")
        pubs = list(iss.eligible_set)

        proof = build_proof(
            secret=a.secret,
            feedback="great lectures",
            course="DBMS",
            public_set=pubs,
        )
        ctx = feedback_context("DBMS", "great lectures")
        nb = nullifier_base_for("DBMS")
        assert verify(proof, pubs, ctx, nb) is True

    def test_build_proof_rejects_outsider(self):
        iss = Issuer()
        for name in ["A", "B", "C"]:
            iss.issue(name)
        pubs = list(iss.eligible_set)
        outsider = 12345
        with pytest.raises(ValueError):
            build_proof(
                secret=outsider,
                feedback="hi",
                course="DBMS",
                public_set=pubs,
            )

    def test_build_proof_rejects_empty_feedback(self):
        iss = Issuer()
        a = iss.issue("A")
        iss.issue("B")
        iss.issue("C")
        pubs = list(iss.eligible_set)
        with pytest.raises(ValueError):
            build_proof(secret=a.secret, feedback="", course="DBMS", public_set=pubs)
        with pytest.raises(ValueError):
            build_proof(secret=a.secret, feedback="   ", course="DBMS", public_set=pubs)

    def test_build_proof_rejects_empty_course(self):
        iss = Issuer()
        a = iss.issue("A")
        iss.issue("B")
        iss.issue("C")
        pubs = list(iss.eligible_set)
        with pytest.raises(ValueError):
            build_proof(secret=a.secret, feedback="hi", course="", public_set=pubs)

    def test_feedback_context_binds_hash(self):
        c1 = feedback_context("DBMS", "hello")
        c2 = feedback_context("DBMS", "hello!")
        c3 = feedback_context("OS", "hello")
        assert c1 != c2
        assert c1 != c3

    def test_proof_tampered_feedback_rejected(self):
        iss = Issuer()
        a = iss.issue("A")
        iss.issue("B")
        iss.issue("C")
        iss.issue("D")
        pubs = list(iss.eligible_set)
        proof = build_proof(
            secret=a.secret,
            feedback="good",
            course="DBMS",
            public_set=pubs,
        )
        tampered_ctx = feedback_context("DBMS", "bad")
        nb = nullifier_base_for("DBMS")
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, tampered_ctx, nb)

    def test_proof_includes_nullifier(self):
        """The proof must carry a top-level nullifier field."""
        iss = Issuer()
        a = iss.issue("A")
        iss.issue("B")
        iss.issue("C")
        pubs = list(iss.eligible_set)
        proof = build_proof(
            secret=a.secret,
            feedback="hi",
            course="DBMS",
            public_set=pubs,
        )
        assert "nullifier" in proof
        assert isinstance(proof["nullifier"], int)
        # Components must include the M commitment.
        for comp in proof["components"]:
            assert "M" in comp

    def test_nullifier_deterministic_in_secret_and_course(self):
        iss = Issuer()
        for name in ["A", "B", "C"]:
            iss.issue(name)
        a = iss.issue("D")
        pubs = list(iss.eligible_set)
        p1 = build_proof(secret=a.secret, feedback="fb1", course="DBMS", public_set=pubs)
        p2 = build_proof(secret=a.secret, feedback="fb2", course="DBMS", public_set=pubs)
        assert p1["nullifier"] == p2["nullifier"]

    def test_nullifier_differs_across_courses(self):
        iss = Issuer()
        for name in ["A", "B", "C"]:
            iss.issue(name)
        a = iss.issue("D")
        pubs = list(iss.eligible_set)
        p1 = build_proof(secret=a.secret, feedback="fb", course="DBMS", public_set=pubs)
        p2 = build_proof(secret=a.secret, feedback="fb", course="OS", public_set=pubs)
        assert p1["nullifier"] != p2["nullifier"]
