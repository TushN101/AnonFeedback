"""Flask entry point for AnonFeedback.

Run::

    python app.py
    # then open http://127.0.0.1:5000/

Or via Flask CLI::

    flask --app app run
"""

from __future__ import annotations

import logging

from flask import Flask

from config import Config
from credential.issuer import Issuer
from server.routes import register_routes
from server.store import get_store


def create_app(config_class: type = Config) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_class)

    register_routes(app)

    # Seed demo data on first run for convenience.
    _seed_demo_data(app)

    # Disable the default request logger: it writes IP + timestamp + path to
    # stdout for every request, which is exactly the kind of metadata that
    # could correlate a submission to a student. See plan.md §5.3 L8.
    if app.config.get("DISABLE_REQUEST_LOGGING", True):
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

    return app


def _seed_demo_data(app: Flask) -> None:
    """Seed a few eligible students and courses so the small-anonymity-set
    guard (plan.md §5.3 L4) doesn't block immediate experimentation.

    The seeded students' secrets are written to a file
    ``demo-secrets.txt`` in the working directory so the demonstrator can
    hand them out. (In a real deployment there would be no such file; the
    secret would be issued to each student individually over a secure
    channel.)
    """
    issuer: Issuer = get_store().issuer
    if issuer.eligible_size() > 0:
        return  # already seeded

    secrets_lines = []
    for name in app.config.get("SEED_STUDENTS", []):
        result = issuer.issue(name)
        secrets_lines.append(
            f"{result.name} | student_id={result.student_id} | "
            f"secret={result.secret}"
        )
    for course in app.config.get("SEED_COURSES", []):
        issuer.add_course(course)

    try:
        with open("demo-secrets.txt", "w", encoding="utf-8") as fh:
            fh.write(
                "# AnonFeedback demo — pre-seeded student secrets.\n"
                "# Each line is: <name> | student_id=... | secret=...\n"
                "# Hand these to the corresponding student via an out-of-band\n"
                "# channel (chat, paper slip, etc.). The server does NOT keep\n"
                "# these secrets after issuance.\n\n"
            )
            fh.write("\n".join(secrets_lines))
            fh.write("\n")
    except OSError:
        # Non-fatal: seeding is a convenience, not a requirement.
        pass


# Module-level app for `flask --app app run` and `python app.py`.
app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
