"""Flask routes for AnonFeedback.

Routes are split into:

* HTML pages: ``/``, ``/admin``, ``/student``, ``/feedback``.
* JSON API: ``/api/admin/*``, ``/api/student/*``, ``/api/submit``,
  ``/api/feedback``.

All JSON endpoints return either ``{"ok": true, ...}`` on success or
``{"ok": false, "error": "<short reason>"}`` with an appropriate HTTP status on
failure. Error reasons are deliberately generic on the verification path to
avoid leaking signal about *which* part of the proof failed.
"""

from __future__ import annotations

import time

from flask import Flask, current_app, jsonify, render_template, request

from credential import build_proof, feedback_context
from credential.issuer import Issuer
from server.store import FeedbackRecord, get_store
from zkp import ProofValidationError, deserialize_proof, serialize_proof, verify
from zkp.group import in_subgroup, nullifier_base_for


# --- input validation helpers ----------------------------------------------


def _parse_int_field(value, field_name: str) -> int:
    """Parse a JSON field that should be a base-10 integer string or int."""
    if value is None:
        raise ValueError(f"missing {field_name}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"{field_name} is not a valid integer")
    raise ValueError(f"{field_name} must be an integer or string")


def _validate_feedback_text(text) -> str:
    if not isinstance(text, str):
        raise ValueError("feedback must be a string")
    text = text.strip()
    if not text:
        raise ValueError("feedback is empty")
    max_len = current_app.config.get("MAX_FEEDBACK_LENGTH", 4000)
    if len(text) > max_len:
        raise ValueError(f"feedback exceeds {max_len} characters")
    return text


def _validate_course(course) -> str:
    """Basic shape validation for a course id (whitespace + length).

    Membership in the predefined courses list is enforced separately by
    :func:`_require_known_course` on the submission path.
    """
    if not isinstance(course, str):
        raise ValueError("course must be a string")
    course = course.strip()
    if not course:
        raise ValueError("course is empty")
    max_len = current_app.config.get("MAX_COURSE_LENGTH", 64)
    if len(course) > max_len:
        raise ValueError(f"course exceeds {max_len} characters")
    return course


def _require_known_course(course: str) -> None:
    """Reject course ids not in the predefined list (or admin-added at runtime).

    The student UI presents a fixed dropdown so users cannot type arbitrary
    course names. The server independently rejects any submission whose
    course is not in ``issuer.courses`` — defending against direct API calls
    that bypass the UI.
    """
    issuer = get_store().issuer
    if course not in issuer.courses:
        raise ValueError(
            f"unknown course '{course}'; pick one of: {', '.join(issuer.courses)}"
        )


# --- HTML routes ------------------------------------------------------------


def register_html_routes(app: Flask) -> None:
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/admin")
    def admin_page():
        return render_template("admin.html")

    @app.get("/student")
    def student_page():
        return render_template("student.html")

    @app.get("/feedback")
    def feedback_page():
        return render_template("feedback.html")


# --- JSON API ---------------------------------------------------------------


def register_api_routes(app: Flask) -> None:
    @app.get("/api/admin/eligible")
    def api_eligible():
        store = get_store()
        issuer = store.issuer
        return jsonify(
            {
                "ok": True,
                "eligible_set": issuer.public_set_view(),
                "size": issuer.eligible_size(),
                "min_required": app.config["MIN_ELIGIBLE_SET_SIZE"],
            }
        )

    @app.get("/api/admin/students")
    def api_students():
        """Admin-only view of the issuance log.

        This is the *only* place where names and public keys appear together.
        It exists for the admin UI to render the issuance table. It is NOT
        consulted by the verification path.
        """
        issuer = get_store().issuer
        rows = []
        for name, (sid, pub) in issuer.issuance_log.items():
            rows.append(
                {
                    "student_id": sid,
                    "name": name,
                    "public_key": str(pub),
                }
            )
        return jsonify({"ok": True, "students": rows})

    @app.post("/api/admin/issue")
    def api_issue():
        data = request.get_json(silent=True) or {}
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            return jsonify({"ok": False, "error": "name is required"}), 400
        issuer = get_store().issuer
        try:
            result = issuer.issue(name)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "result": result.as_dict()})

    @app.post("/api/admin/course")
    def api_add_course():
        data = request.get_json(silent=True) or {}
        course = data.get("course")
        if not isinstance(course, str) or not course.strip():
            return jsonify({"ok": False, "error": "course is required"}), 400
        try:
            get_store().issuer.add_course(course)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "courses": list(get_store().issuer.courses)})

    @app.get("/api/admin/courses")
    def api_courses():
        return jsonify({"ok": True, "courses": list(get_store().issuer.courses)})

    @app.get("/api/admin/feedback")
    def api_admin_feedback():
        """Admin view of submitted feedback.

        Includes the per-course nullifier (for audit / debugging) — but the
        nullifier is NOT a student identifier: it is unlinkable across
        courses and across students (see ``zkp.group.nullifier_base_for``).
        No student name, student id, secret, or public key is exposed here.
        """
        store = get_store()
        return jsonify({"ok": True, "feedback": store.admin_feedback_view()})

    # --- student-side helpers ----------------------------------------------

    @app.post("/api/student/prove")
    def api_student_prove():
        """Build a proof on behalf of the student UI.

        In a "real" deployment the student would generate the proof entirely
        client-side in JS. For this Python demo, we run the same
        ``credential.build_proof`` code server-side as a stateless helper.
        The endpoint does NOT store the secret, the feedback, or the proof —
        it just returns the proof for the student's browser to submit.

        See plan.md §4.2 note.
        """
        data = request.get_json(silent=True) or {}
        try:
            secret = _parse_int_field(data.get("secret"), "secret")
            feedback = _validate_feedback_text(data.get("feedback"))
            course = _validate_course(data.get("course"))
            _require_known_course(course)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        store = get_store()
        issuer = store.issuer

        # Small-anonymity-set guard (plan.md §5.3 L4).
        if issuer.eligible_size() < app.config["MIN_ELIGIBLE_SET_SIZE"]:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": (
                            "anonymity set too small: at least "
                            f"{app.config['MIN_ELIGIBLE_SET_SIZE']} eligible "
                            "students are required before feedback can be "
                            "submitted"
                        ),
                    }
                ),
                400,
            )

        public_set = list(issuer.eligible_set)
        try:
            proof = build_proof(secret=secret, feedback=feedback, course=course, public_set=public_set)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        return jsonify(
            {
                "ok": True,
                "proof": serialize_proof(proof),
                "feedback": feedback,
                "course": course,
            }
        )

    # --- submission / verification -----------------------------------------

    @app.post("/api/submit")
    def api_submit():
        """Verify a proof and store the feedback.

        Request body::

            {"feedback": "...", "course": "DBMS",
             "proof": {challenge, nullifier, components}}

        The verifier consults ONLY the public eligible set. It never reads the
        issuance log. See plan.md §3.5 step (6).

        Duplicate detection: the proof's nullifier ``N = h^{x_k}`` (where
        ``h = nullifier_base_for(course)``) is deterministic in
        ``(student_secret, course)``. If a record with the same nullifier is
        already stored, the submission is rejected with 409 Conflict —
        without revealing which student already submitted.
        """
        data = request.get_json(silent=True) or {}
        try:
            feedback = _validate_feedback_text(data.get("feedback"))
            course = _validate_course(data.get("course"))
            _require_known_course(course)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        proof_in = data.get("proof")
        try:
            proof = deserialize_proof(proof_in)
        except ValueError:
            return jsonify({"ok": False, "error": "proof is malformed"}), 400

        store = get_store()
        issuer = store.issuer

        # Small-anonymity-set guard.
        if issuer.eligible_size() < app.config["MIN_ELIGIBLE_SET_SIZE"]:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": (
                            "anonymity set too small: at least "
                            f"{app.config['MIN_ELIGIBLE_SET_SIZE']} eligible "
                            "students are required"
                        ),
                    }
                ),
                400,
            )

        public_set = list(issuer.eligible_set)
        if len(proof["components"]) != len(public_set):
            return (
                jsonify({"ok": False, "error": "proof length does not match eligible set"}),
                400,
            )

        # Recompute the per-course nullifier base h = G2^{H(course)} and verify
        # the proof against it. The proof's published nullifier must equal
        # h^{x_k} for the same x_k whose knowledge of Y_k = g^{x_k} is proved.
        nullifier_base = nullifier_base_for(course)
        context = feedback_context(course, feedback)
        try:
            verify(proof, public_set, context, nullifier_base)
        except ProofValidationError:
            # Generic, non-revealing error.
            return jsonify({"ok": False, "error": "proof rejected"}), 400

        # Duplicate detection: same nullifier for same (student, course) means
        # this student has already submitted feedback for this course.
        nullifier = proof["nullifier"]
        if store.has_nullifier(nullifier):
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": (
                            "duplicate feedback: you have already submitted "
                            f"feedback for {course}. Each student may submit "
                            "only once per course."
                        ),
                    }
                ),
                409,
            )

        record = FeedbackRecord(
            feedback=feedback,
            course=course,
            proof=proof,
            nullifier=nullifier,
            timestamp=time.time(),
            verified=True,
        )
        store.add_feedback(record)
        return jsonify({"ok": True, "stored": True})

    @app.get("/api/feedback")
    def api_feedback():
        store = get_store()
        return jsonify({"ok": True, "feedback": store.feedback_view()})


def register_routes(app: Flask) -> None:
    register_html_routes(app)
    register_api_routes(app)
