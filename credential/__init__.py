"""Credential layer for AnonFeedback.

This module orchestrates the protocol on top of :mod:`zkp`:

* :mod:`credential.issuer` — college-side: creates credentials, manages the
  eligible set ``S``.
* :mod:`credential.holder` — student-side: builds a proof for a feedback
  payload.
"""

from .holder import build_proof, feedback_context
from .issuer import IssueResult, Issuer

__all__ = ["Issuer", "IssueResult", "build_proof", "feedback_context"]
