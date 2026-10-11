"""Educational ZKP module for AnonFeedback.

Public API::

    from zkp import prove, verify, ProofValidationError
    from zkp import serialize_proof, deserialize_proof
"""

from .group import deserialize_proof, serialize_proof
from .or_proof import ProofValidationError, prove, verify

__all__ = [
    "prove",
    "verify",
    "ProofValidationError",
    "serialize_proof",
    "deserialize_proof",
]
