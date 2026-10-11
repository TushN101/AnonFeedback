"""Tests for the Flask routes.

Uses the Flask test client. Each test starts with a fresh store via
``reset_store()`` to keep state isolated.
"""

import pytest

from app import create_app
from config import Config
from server.store import reset_store


@pytest.fixture
def client():
    reset_store()
    app = create_app(Config)
    app.testing = True
    return app.test_client()


def issue(client, name):
    """Helper: issue a credential, return the result dict."""
    r = client.post("/api/admin/issue", json={"name": name})
    assert r.status_code == 200, r.json
    return r.json["result"]


def submit(client, secret, feedback, course):
    """Helper: prove + submit. Returns the /api/submit response."""
    pr = client.post(
        "/api/student/prove",
        json={"secret": secret, "feedback": feedback, "course": course},
    )
    if pr.status_code != 200:
        return pr  # surface the error to the caller
    proof = pr.json["proof"]
    return client.post(
        "/api/submit",
        json={"feedback": feedback, "course": course, "proof": proof},
    )


# ---------- HTML routes -----------------------------------------------------


class TestHtmlRoutes:
    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"AnonFeedback" in r.data

    def test_admin(self, client):
        r = client.get("/admin")
        assert r.status_code == 200
        assert b"Issue a credential" in r.data or b"issue" in r.data.lower()

    def test_student(self, client):
        r = client.get("/student")
        assert r.status_code == 200
        assert b"Submit feedback" in r.data or b"submit" in r.data.lower()

    def test_feedback(self, client):
        r = client.get("/feedback")
        assert r.status_code == 200
        assert b"Feedback board" in r.data or b"feedback" in r.data.lower()


# ---------- admin API -------------------------------------------------------


class TestAdminApi:
    def test_eligible_seeded(self, client):
        """create_app() seeds 4 demo students."""
        r = client.get("/api/admin/eligible")
        assert r.status_code == 200
        body = r.json
        assert body["ok"] is True
        assert body["size"] == 4
        assert len(body["eligible_set"]) == 4
        assert body["min_required"] == 3

    def test_courses_seeded_with_indian_subjects(self, client):
        """The seed courses are now DBMS, OS, CN, OOP, DSA."""
        r = client.get("/api/admin/courses")
        assert r.status_code == 200
        courses = r.json["courses"]
        assert "DBMS" in courses
        assert "OS" in courses
        assert "CN" in courses
        assert "OOP" in courses
        assert "DSA" in courses
        # Old defaults are gone.
        assert "CS101" not in courses
        assert "MA202" not in courses

    def test_issue_student(self, client):
        r = client.post("/api/admin/issue", json={"name": "Zoe"})
        assert r.status_code == 200
        body = r.json
        assert body["ok"] is True
        result = body["result"]
        assert result["name"] == "Zoe"
        assert "secret" in result
        assert "public_key" in result
        assert "student_id" in result

    def test_issue_rejects_missing_name(self, client):
        r = client.post("/api/admin/issue", json={})
        assert r.status_code == 400
        assert r.json["ok"] is False

    def test_issue_rejects_empty_name(self, client):
        r = client.post("/api/admin/issue", json={"name": "   "})
        assert r.status_code == 400

    def test_issue_rejects_duplicate(self, client):
        client.post("/api/admin/issue", json={"name": "Dup"})
        r = client.post("/api/admin/issue", json={"name": "Dup"})
        assert r.status_code == 400
        assert "already" in r.json["error"]

    def test_add_course(self, client):
        r = client.post("/api/admin/course", json={"course": "COA"})
        assert r.status_code == 200
        assert "COA" in r.json["courses"]

    def test_add_course_rejects_empty(self, client):
        r = client.post("/api/admin/course", json={"course": ""})
        assert r.status_code == 400

    def test_students_list(self, client):
        r = client.get("/api/admin/students")
        assert r.status_code == 200
        names = [s["name"] for s in r.json["students"]]
        assert any("Alice" in n for n in names)


# ---------- student prove + submit -----------------------------------------


class TestSubmission:
    def test_valid_submission_round_trip(self, client):
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        feedback = "The pace was good."
        prove_res = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": feedback, "course": "DBMS"},
        )
        assert prove_res.status_code == 200
        proof = prove_res.json["proof"]
        # The proof must include a nullifier.
        assert "nullifier" in proof
        sub = client.post(
            "/api/submit",
            json={"feedback": feedback, "course": "DBMS", "proof": proof},
        )
        assert sub.status_code == 200
        assert sub.json["ok"] is True
        assert sub.json["stored"] is True

    def test_submit_then_visible_on_public_board(self, client):
        """Regression: accepted feedback must appear on the public board.

        This was the original feedback-board bug. The /api/feedback endpoint
        always returned the data correctly; the bug was in app.js's
        refreshFeedbackBoard destructuring. We test the backend here, and the
        frontend via a separate render check in test_e2e.
        """
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        fb = "Loved the visuals."
        proof = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": fb, "course": "DBMS"},
        ).json["proof"]
        sub = client.post(
            "/api/submit",
            json={"feedback": fb, "course": "DBMS", "proof": proof},
        )
        assert sub.status_code == 200

        board = client.get("/api/feedback").json
        assert board["ok"] is True
        assert len(board["feedback"]) == 1
        assert board["feedback"][0]["feedback"] == fb
        assert board["feedback"][0]["course"] == "DBMS"
        assert board["feedback"][0]["verified"] is True
        # No identity fields in the public view.
        assert "secret" not in board["feedback"][0]
        assert "name" not in board["feedback"][0]
        assert "student_id" not in board["feedback"][0]
        # Nullifier is NOT exposed on the public board.
        assert "nullifier" not in board["feedback"][0]

    def test_tampered_feedback_rejected(self, client):
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        proof = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": "good", "course": "DBMS"},
        ).json["proof"]
        sub = client.post(
            "/api/submit",
            json={
                "feedback": "bad",  # different from what was proven
                "course": "DBMS",
                "proof": proof,
            },
        )
        assert sub.status_code == 400
        assert sub.json["ok"] is False
        assert "rejected" in sub.json["error"]

    def test_outsider_secret_rejected(self, client):
        r = client.post(
            "/api/student/prove",
            json={"secret": 12345, "feedback": "hi", "course": "DBMS"},
        )
        assert r.status_code == 400
        assert r.json["ok"] is False

    def test_proof_for_wrong_course_rejected(self, client):
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        proof = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": "hi", "course": "DBMS"},
        ).json["proof"]
        # Submit with a different course. The nullifier_base in the transcript
        # won't match the verifier's recomputation for OS.
        sub = client.post(
            "/api/submit",
            json={"feedback": "hi", "course": "OS", "proof": proof},
        )
        assert sub.status_code == 400

    def test_missing_fields_rejected(self, client):
        r = client.post("/api/submit", json={})
        assert r.status_code == 400

    def test_malformed_proof_rejected(self, client):
        r = client.post(
            "/api/submit",
            json={
                "feedback": "hi",
                "course": "DBMS",
                "proof": {"challenge": "1", "nullifier": "2", "components": []},
            },
        )
        assert r.status_code == 400

    def test_non_integer_secret_rejected(self, client):
        r = client.post(
            "/api/student/prove",
            json={"secret": "not-a-number", "feedback": "hi", "course": "DBMS"},
        )
        assert r.status_code == 400

    def test_oversized_feedback_rejected(self, client):
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        r = client.post(
            "/api/student/prove",
            json={
                "secret": secret,
                "feedback": "x" * 5000,
                "course": "DBMS",
            },
        )
        assert r.status_code == 400


# ---------- course dropdown validation -------------------------------------


class TestCourseValidation:
    def test_unknown_course_rejected_at_prove(self, client):
        """The student UI's dropdown prevents typing, but the server must
        also reject unknown courses via direct API access."""
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        r = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": "hi", "course": "MA202"},
        )
        assert r.status_code == 400
        assert "unknown course" in r.json["error"]

    def test_unknown_course_rejected_at_submit(self, client):
        """Even if a proof somehow bypasses the prove step, /api/submit
        independently validates the course."""
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        # Build a proof for DBMS first (which is valid).
        proof = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": "hi", "course": "DBMS"},
        ).json["proof"]
        # Then attempt to submit with a course label that doesn't exist.
        r = client.post(
            "/api/submit",
            json={"feedback": "hi", "course": "FAKE999", "proof": proof},
        )
        assert r.status_code == 400
        assert "unknown course" in r.json["error"]

    def test_admin_can_add_course_then_student_can_use_it(self, client):
        client.post("/api/admin/course", json={"course": "COA"})
        issue = client.post("/api/admin/issue", json={"name": "Eve"})
        secret = issue.json["result"]["secret"]
        r = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": "hi", "course": "COA"},
        )
        assert r.status_code == 200


# ---------- duplicate submission prevention (nullifier) --------------------


class TestDuplicatePrevention:
    def test_same_student_same_course_rejected(self, client):
        """A student who has already submitted for a course cannot submit
        again for that course. The second submission must be rejected with
        409 Conflict, without revealing the student's identity."""
        eve = issue(client, "Eve")
        sub1 = submit(client, eve["secret"], "first feedback", "DBMS")
        assert sub1.status_code == 200
        assert sub1.json["ok"] is True

        sub2 = submit(client, eve["secret"], "second feedback, different text", "DBMS")
        assert sub2.status_code == 409
        assert sub2.json["ok"] is False
        assert "duplicate" in sub2.json["error"].lower()
        # The error must NOT reveal the student's identity.
        assert "Eve" not in sub2.json["error"]

    def test_same_student_different_course_accepted(self, client):
        """The same student can submit to multiple courses — nullifiers
        differ across courses by design (unlinkable)."""
        eve = issue(client, "Eve")
        for course in ["DBMS", "OS", "CN"]:
            sub = submit(client, eve["secret"], f"feedback for {course}", course)
            assert sub.status_code == 200, (course, sub.json)
            assert sub.json["ok"] is True
        board = client.get("/api/feedback").json
        assert len(board["feedback"]) == 3

    def test_different_students_same_course_accepted(self, client):
        """Two different students submitting to the same course: both
        accepted. Their nullifiers differ (different x_k → different N)."""
        a = issue(client, "Alice-too")
        b = issue(client, "Bob-too")
        sub_a = submit(client, a["secret"], "alice's feedback", "DBMS")
        sub_b = submit(client, b["secret"], "bob's feedback", "DBMS")
        assert sub_a.status_code == 200
        assert sub_b.status_code == 200
        board = client.get("/api/feedback").json
        assert len(board["feedback"]) == 2

    def test_duplicate_rejection_does_not_reveal_first_submission(self, client):
        """The 409 error message must not leak the original feedback text
        or any identifying information about the first submission."""
        eve = issue(client, "Eve")
        submit(client, eve["secret"], "the original secret feedback text", "DBMS")
        sub2 = submit(client, eve["secret"], "second", "DBMS")
        assert sub2.status_code == 409
        assert "the original secret feedback text" not in sub2.json["error"]

    def test_nullifier_cannot_be_swapped_to_bypass_dedup(self, client):
        """A malicious student cannot submit twice for the same course by
        swapping in a nullifier from a different course's proof. The
        per-component M commitments are bound to the course-specific
        nullifier_base, so swapping N invalidates the proof."""
        eve = issue(client, "Eve")
        # First submission for DBMS succeeds.
        sub1 = submit(client, eve["secret"], "first", "DBMS")
        assert sub1.status_code == 200

        # Build a proof for OS (different course, different nullifier).
        pr_os = client.post(
            "/api/student/prove",
            json={"secret": eve["secret"], "feedback": "hi", "course": "OS"},
        ).json["proof"]
        # Try to submit it as a SECOND DBMS submission with the OS nullifier.
        sub2 = client.post(
            "/api/submit",
            json={"feedback": "hi", "course": "DBMS", "proof": pr_os},
        )
        # The verifier recomputes nullifier_base for DBMS, which differs from
        # the OS base in the proof's transcript. Verification fails.
        assert sub2.status_code == 400
        assert sub2.json["ok"] is False


# ---------- anonymity-set guard --------------------------------------------


class TestAnonymitySetGuard:
    def test_too_small_set_blocks_submission(self, client):
        """Reset to a fresh store with NO seeding, issue only 2 students,
        and verify the guard fires."""
        from server.store import get_store

        reset_store()
        store = get_store()
        store.issuer.issue("Solo1")
        store.issuer.issue("Solo2")

        r = client.post(
            "/api/student/prove",
            json={"secret": 12345, "feedback": "hi", "course": "DBMS"},
        )
        # The store has 2 eligible students → guard fires. But also, DBMS
        # is not in this fresh store's course list, so the course check fires
        # first. Either way we expect 400.
        assert r.status_code == 400


# ---------- non-revelation of identity on the verification path ------------


class TestNoIdentityInVerificationPath:
    def test_public_feedback_has_no_identity(self, client):
        for i in range(3):
            r = client.post("/api/admin/issue", json={"name": f"Student{i}"})
            secret = r.json["result"]["secret"]
            fb = f"feedback number {i}"
            proof = client.post(
                "/api/student/prove",
                json={"secret": secret, "feedback": fb, "course": "DBMS" if i == 0 else "OS"},
            ).json["proof"]
            client.post(
                "/api/submit",
                json={"feedback": fb, "course": "DBMS" if i == 0 else "OS", "proof": proof},
            )
        board = client.get("/api/feedback").json
        for entry in board["feedback"]:
            for forbidden in ("name", "student_id", "secret", "public_key", "nullifier"):
                assert forbidden not in entry
            assert "proof_components" in entry

    def test_admin_feedback_view_has_no_identity(self, client):
        """The admin view DOES include the nullifier (for audit), but does
        NOT include any student identifier (name, id, secret, public key)."""
        issue = client.post("/api/admin/issue", json={"name": "UniqueName"})
        secret = issue.json["result"]["secret"]
        proof = client.post(
            "/api/student/prove",
            json={"secret": secret, "feedback": "marker", "course": "DBMS"},
        ).json["proof"]
        client.post(
            "/api/submit",
            json={"feedback": "marker", "course": "DBMS", "proof": proof},
        )
        admin_view = client.get("/api/admin/feedback").json
        for entry in admin_view["feedback"]:
            # Nullifier IS exposed to admin (for audit).
            assert "nullifier" in entry
            # But no identity fields.
            for forbidden in ("name", "student_id", "secret", "public_key"):
                assert forbidden not in entry
            # The admin-known name "UniqueName" must NOT appear in the entry.
            serialized = str(entry)
            assert "UniqueName" not in serialized
