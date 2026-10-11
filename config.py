"""Demo configuration for AnonFeedback.

Nothing here is a secret. Group parameters live in :mod:`zkp.params`.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask
    SECRET_KEY = "anonfeedback-demo-key-not-secret"  # demo only; not used to protect secrets

    # Minimum size of the eligible set before submissions are accepted.
    # This mitigates (but does not eliminate) the small-anonymity-set problem
    # described in plan.md §5.3 L4.
    MIN_ELIGIBLE_SET_SIZE = 3

    # Maximum feedback length (characters).
    MAX_FEEDBACK_LENGTH = 4000

    # Maximum course-id length.
    MAX_COURSE_LENGTH = 64

    # Whether to disable the default Flask request logger (we do, to avoid
    # writing IP+timestamp to stdout in a demo about anonymity).
    DISABLE_REQUEST_LOGGING = True

    # Seed data: created on first run for demo convenience.
    SEED_STUDENTS = [
        "Alice (CS, roll 23)",
        "Bob (CS, roll 24)",
        "Carol (CS, roll 25)",
        "Dan (CS, roll 26)",
    ]

    # Predefined list of courses offered by the (simulated) college.
    # These appear as a fixed dropdown in the student UI so that course
    # names are consistent and free-text entry (with its spelling mistakes)
    # is not allowed. The server rejects feedback for any course not in
    # this list (union with any admin-added courses at runtime).
    PREDEFINED_COURSES = ["DBMS", "OS", "CN", "OOP", "DSA"]
    SEED_COURSES = list(PREDEFINED_COURSES)
