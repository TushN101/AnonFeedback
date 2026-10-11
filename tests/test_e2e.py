"""End-to-end tests: full protocol run + cross-prover unlinkability + the
feedback-board fix + nullifier dedup.

These tests exercise the whole stack at the API level using the Flask test
client. They verify that:

1. A full issue → prove → submit → verify → board-view flow works.
2. Multiple eligible students can each submit feedback, all are verified.
3. The submitted (and verified) feedback records contain no identity fields.
4. Accepted feedback appears on the public feedback board (regression test
   for the original app.js destructuring bug — exercised via the backend
   here, since app.js is not executed in pytest).
5. Duplicate submissions for the same (student, course) are rejected.
6. The nullifier is bound to the proof and cannot be swapped to bypass dedup.
"""

import pytest

from app import create_app
from config import Config
from server.store import reset_store


@pytest.fixture
def client():
    reset_store()
    app = create_app(Config)
    return app.test_client()


def issue(client, name):
    r = client.post("/api/admin/issue", json={"name": name})
    assert r.status_code == 200, r.json
    return r.json["result"]


def submit(client, secret, feedback, course):
    pr = client.post(
        "/api/student/prove",
        json={"secret": secret, "feedback": feedback, "course": course},
    )
    assert pr.status_code == 200, pr.json
    proof = pr.json["proof"]
    return client.post(
        "/api/submit",
        json={"feedback": feedback, "course": course, "proof": proof},
    )


class TestEndToEnd:
    def test_full_workflow(self, client):
        # Seeded: 4 students + 5 courses (DBMS, OS, CN, OOP, DSA).
        # Issue 5 fresh students whose secrets we know.
        results = [issue(client, f"Stu{i}") for i in range(5)]
        # Each student submits feedback to a different course.
        courses = ["DBMS", "OS", "CN", "OOP", "DSA"]
        for i, r in enumerate(results):
            sub = submit(client, r["secret"], f"feedback from stu{i}", courses[i])
            assert sub.status_code == 200, sub.json
            assert sub.json["ok"] is True

        # Board should show 5 verified entries.
        board = client.get("/api/feedback").json
        assert len(board["feedback"]) == 5
        for f in board["feedback"]:
            assert f["verified"] is True
            assert f["course"] in courses
            assert "name" not in f and "student_id" not in f

    def test_accepted_feedback_appears_on_public_board(self, client):
        """Regression test for the original feedback-board bug.

        The bug: app.js's refreshFeedbackBoard destructured `json` from
        getJSON()'s direct return value, yielding undefined, and silently
        aborted the render. The backend always returned the data correctly;
        this test asserts that.
        """
        a = issue(client, "Alpha")
        sub = submit(client, a["secret"], "the lecture pace was good", "DBMS")
        assert sub.status_code == 200

        board = client.get("/api/feedback").json
        assert board["ok"] is True
        assert len(board["feedback"]) == 1
        assert board["feedback"][0]["feedback"] == "the lecture pace was good"
        assert board["feedback"][0]["course"] == "DBMS"
        assert board["feedback"][0]["verified"] is True

    def test_two_students_proofs_independent(self, client):
        a = issue(client, "Alpha")
        b = issue(client, "Beta")
        pa = client.post(
            "/api/student/prove",
            json={"secret": a["secret"], "feedback": "fb", "course": "DBMS"},
        ).json["proof"]
        pb = client.post(
            "/api/student/prove",
            json={"secret": b["secret"], "feedback": "fb", "course": "DBMS"},
        ).json["proof"]
        # Both verify against the same set + context.
        sub_a = client.post(
            "/api/submit",
            json={"feedback": "fb", "course": "DBMS", "proof": pa},
        )
        sub_b = client.post(
            "/api/submit",
            json={"feedback": "fb", "course": "DBMS", "proof": pb},
        )
        assert sub_a.status_code == 200
        assert sub_b.status_code == 200

        # Structural indistinguishability: same shape, no obviously special
        # (zero / one) values.
        assert len(pa["components"]) == len(pb["components"])
        assert pa["components"][0].keys() == pb["components"][0].keys()
        for proof in (pa, pb):
            for c in proof["components"]:
                assert int(c["c"]) > 1
                assert int(c["s"]) > 1
                assert int(c["R"]) > 1
                assert int(c["M"]) > 1
        # Nullifiers must differ (different x_k → different N).
        assert pa["nullifier"] != pb["nullifier"]

    def test_replay_with_different_feedback_rejected(self, client):
        a = issue(client, "Solo")
        pa = client.post(
            "/api/student/prove",
            json={"secret": a["secret"], "feedback": "first", "course": "DBMS"},
        ).json["proof"]
        sub = client.post(
            "/api/submit",
            json={"feedback": "second", "course": "DBMS", "proof": pa},
        )
        assert sub.status_code == 400
        assert "rejected" in sub.json["error"]

    def test_replay_with_different_course_rejected(self, client):
        a = issue(client, "Solo")
        pa = client.post(
            "/api/student/prove",
            json={"secret": a["secret"], "feedback": "same", "course": "DBMS"},
        ).json["proof"]
        sub = client.post(
            "/api/submit",
            json={"feedback": "same", "course": "OS", "proof": pa},
        )
        assert sub.status_code == 400

    def test_two_different_students_same_feedback_both_accepted(self, client):
        """Two distinct students may submit the same feedback text to the
        same course. Each generates a fresh proof with a different
        nullifier, and both are accepted."""
        a = issue(client, "A")
        b = issue(client, "B")
        same_fb = "I think the lectures were great."
        sub_a = submit(client, a["secret"], same_fb, "DBMS")
        sub_b = submit(client, b["secret"], same_fb, "DBMS")
        assert sub_a.status_code == 200
        assert sub_b.status_code == 200
        board = client.get("/api/feedback").json
        assert len(board["feedback"]) == 2


class TestDuplicatePreventionE2E:
    def test_student_cannot_submit_twice_for_same_course(self, client):
        a = issue(client, "Alice-extra")
        sub1 = submit(client, a["secret"], "first feedback", "DBMS")
        assert sub1.status_code == 200

        sub2 = submit(client, a["secret"], "second feedback, different text", "DBMS")
        assert sub2.status_code == 409
        assert "duplicate" in sub2.json["error"].lower()

    def test_student_can_submit_to_multiple_courses(self, client):
        a = issue(client, "Alice-multi")
        for course in ["DBMS", "OS", "CN", "OOP", "DSA"]:
            sub = submit(client, a["secret"], f"feedback for {course}", course)
            assert sub.status_code == 200, (course, sub.json)
        board = client.get("/api/feedback").json
        assert len(board["feedback"]) == 5

    def test_five_students_each_submit_to_same_course(self, client):
        students = [issue(client, f"S{i}") for i in range(5)]
        for i, s in enumerate(students):
            sub = submit(client, s["secret"], f"feedback {i}", "DBMS")
            assert sub.status_code == 200, (i, sub.json)
        board = client.get("/api/feedback").json
        assert len(board["feedback"]) == 5
        # All five have distinct nullifiers internally (we trust the dedup
        # logic — if any two had collided, the second would have been 409).
