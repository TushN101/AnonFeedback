"""Tests for the ZKP module: the 1-out-of-n OR proof of set membership with a
course-scoped nullifier.

Covers completeness, soundness, zero-knowledge (unlinkability) at the
transcript level, nullifier correctness, tampering attacks, and a range of
malformed-input scenarios.
"""

import pytest

from zkp import (
    ProofValidationError,
    deserialize_proof,
    prove,
    serialize_proof,
    verify,
)
from zkp.group import in_subgroup, modexp, nullifier_base_for, rand_scalar
from zkp.params import G, P, Q


# ---------- fixtures --------------------------------------------------------


@pytest.fixture
def small_set():
    """A set of 5 (secret, public_key) pairs."""
    secrets = [rand_scalar() for _ in range(5)]
    pubs = [modexp(G, s) for s in secrets]
    return secrets, pubs


@pytest.fixture
def big_set():
    """A set of 20 pairs — closer to a realistic class size."""
    secrets = [rand_scalar() for _ in range(20)]
    pubs = [modexp(G, s) for s in secrets]
    return secrets, pubs


@pytest.fixture
def null_base():
    """A per-course nullifier base for the test course 'DBMS'."""
    return nullifier_base_for("DBMS")


# ---------- completeness ----------------------------------------------------


class TestCompleteness:
    def test_honest_prover_accepts_small_set(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "feedback:DBMS:hello", null_base)
        assert verify(proof, pubs, "feedback:DBMS:hello", null_base) is True

    def test_honest_prover_accepts_big_set(self, big_set, null_base):
        secrets, pubs = big_set
        for k in (0, 7, 19):
            proof = prove(secrets[k], pubs[k], pubs, "ctx", null_base)
            assert verify(proof, pubs, "ctx", null_base) is True

    def test_prover_at_any_index_produces_accepting_proof(self, small_set, null_base):
        secrets, pubs = small_set
        for k in range(len(pubs)):
            proof = prove(secrets[k], pubs[k], pubs, "ctx", null_base)
            assert verify(proof, pubs, "ctx", null_base) is True


# ---------- nullifier properties -------------------------------------------


class TestNullifier:
    def test_nullifier_is_deterministic_in_secret_and_course(self, small_set):
        """Same (x, course) → same nullifier N."""
        secrets, pubs = small_set
        nb_dbms = nullifier_base_for("DBMS")
        p1 = prove(secrets[2], pubs[2], pubs, "ctx-1", nb_dbms)
        p2 = prove(secrets[2], pubs[2], pubs, "ctx-2", nb_dbms)
        assert p1["nullifier"] == p2["nullifier"]

    def test_nullifier_differs_across_courses(self, small_set):
        """Same student, different course → different (unlinkable) nullifier."""
        secrets, pubs = small_set
        nb_dbms = nullifier_base_for("DBMS")
        nb_os = nullifier_base_for("OS")
        p1 = prove(secrets[2], pubs[2], pubs, "ctx", nb_dbms)
        p2 = prove(secrets[2], pubs[2], pubs, "ctx", nb_os)
        assert p1["nullifier"] != p2["nullifier"]

    def test_nullifier_differs_across_students(self, small_set, null_base):
        """Same course, different students → different nullifiers."""
        secrets, pubs = small_set
        p1 = prove(secrets[0], pubs[0], pubs, "ctx", null_base)
        p2 = prove(secrets[1], pubs[1], pubs, "ctx", null_base)
        assert p1["nullifier"] != p2["nullifier"]

    def test_nullifier_equals_h_secret(self, small_set, null_base):
        """The published nullifier must equal h^{x_k}."""
        secrets, pubs = small_set
        k = 2
        proof = prove(secrets[k], pubs[k], pubs, "ctx", null_base)
        expected = modexp(null_base, secrets[k])
        assert proof["nullifier"] == expected

    def test_tampered_nullifier_rejected(self, small_set, null_base):
        """Changing N after proof generation breaks the Chaum-Pedersen check
        (and the transcript check)."""
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        # Bump the nullifier by 1. This must invalidate the proof.
        proof["nullifier"] = (proof["nullifier"] + 1) % P
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)

    def test_nullifier_cannot_be_swapped_between_courses(self, small_set):
        """A malicious student cannot use a DBMS-derived nullifier to bypass
        dedup for OS. The nullifier_base in the transcript must match what
        the verifier expects for the course."""
        secrets, pubs = small_set
        nb_dbms = nullifier_base_for("DBMS")
        nb_os = nullifier_base_for("OS")
        proof_for_dbms = prove(secrets[2], pubs[2], pubs, "ctx", nb_dbms)
        # Verifier expects the OS nullifier base. The transcript's h was
        # nb_dbms, so verification against nb_os must fail.
        with pytest.raises(ProofValidationError):
            verify(proof_for_dbms, pubs, "ctx", nb_os)


# ---------- soundness -------------------------------------------------------


class TestSoundness:
    def test_outsider_cannot_prove(self, small_set, null_base):
        secrets, pubs = small_set
        outsider = rand_scalar()
        outsider_pub = modexp(G, outsider)
        with pytest.raises(ValueError):
            prove(outsider, outsider_pub, pubs, "ctx", null_base)

    def test_proof_for_one_set_rejected_for_another(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        other_pubs = pubs[:2] + pubs[3:]
        with pytest.raises(ProofValidationError):
            verify(proof, other_pubs, "ctx", null_base)

    def test_tampered_context_rejected(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "feedback:DBMS:hello", null_base)
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "feedback:DBMS:hello-tampered", null_base)

    def test_tampered_challenge_rejected(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        proof["challenge"] = (proof["challenge"] + 1) % Q
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)

    def test_tampered_component_s_rejected(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        proof["components"][0]["s"] = (proof["components"][0]["s"] + 1) % Q
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)

    def test_tampered_component_M_rejected(self, small_set, null_base):
        """Tampering the per-component M (the Chaum-Pedersen commitment for
        the nullifier) must be detected."""
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        proof["components"][0]["M"] = (proof["components"][0]["M"] + 1) % P
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)

    def test_tampered_component_c_rejected(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        proof["components"][0]["c"] = (proof["components"][0]["c"] + 1) % Q
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)

    def test_tampered_R_rejected(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        proof["components"][0]["R"] = (proof["components"][0]["R"] + 1) % P
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)

    def test_random_proof_rejected(self, small_set, null_base):
        """A proof made entirely of random numbers must never verify."""
        _, pubs = small_set
        from zkp.or_proof import _transcript_challenge  # internal but stable
        n = len(pubs)
        components = []
        for _ in range(n):
            R = modexp(G, rand_scalar())
            M = modexp(null_base, rand_scalar())
            c = rand_scalar()
            s = rand_scalar()
            components.append({"R": R, "M": M, "c": c, "s": s})
        R_list = [c["R"] for c in components]
        M_list = [c["M"] for c in components]
        N = modexp(null_base, rand_scalar())  # arbitrary
        challenge = _transcript_challenge(N, null_base, R_list, M_list, pubs, "ctx")
        proof = {"challenge": challenge, "nullifier": N, "components": components}
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", null_base)


# ---------- zero-knowledge (unlinkability of transcripts) ------------------


class TestZeroKnowledge:
    def test_two_proofs_by_same_prover_have_different_transcripts(
        self, small_set, null_base
    ):
        secrets, pubs = small_set
        p1 = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        p2 = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        # Transcripts differ (fresh randomness).
        assert p1 != p2
        r1 = [c["R"] for c in p1["components"]]
        r2 = [c["R"] for c in p2["components"]]
        assert r1 != r2
        # Nullifier is the SAME (deterministic in x_k and course) — that's
        # the dedup property.
        assert p1["nullifier"] == p2["nullifier"]

    def test_proof_does_not_reveal_index(self, small_set, big_set, null_base):
        secrets, pubs = big_set
        for k in (0, 5, 10, 15, 19):
            proof = prove(secrets[k], pubs[k], pubs, "ctx", null_base)
            assert verify(proof, pubs, "ctx", null_base) is True
            for comp in proof["components"]:
                assert in_subgroup(comp["R"])
                assert in_subgroup(comp["M"])
                assert in_subgroup(modexp(G, comp["s"]))


# ---------- serialisation round-trip ---------------------------------------


class TestSerialisation:
    def test_serialize_deserialize_round_trip(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        serialised = serialize_proof(proof)
        deserialised = deserialize_proof(serialised)
        assert deserialised == proof

    def test_deserialize_rejects_non_dict(self):
        with pytest.raises(ValueError):
            deserialize_proof([])

    def test_deserialize_rejects_missing_nullifier(self):
        with pytest.raises(ValueError):
            deserialize_proof(
                {"challenge": "1", "components": [{"R": "1", "M": "2", "c": "3", "s": "4"}]}
            )

    def test_deserialize_rejects_missing_field(self):
        with pytest.raises(ValueError):
            deserialize_proof({"challenge": "1", "nullifier": "5"})

    def test_deserialize_rejects_non_integer(self):
        with pytest.raises(ValueError):
            deserialize_proof(
                {
                    "challenge": "not-an-int",
                    "nullifier": "1",
                    "components": [{"R": "1", "M": "2", "c": "3", "s": "4"}],
                }
            )

    def test_deserialize_rejects_malformed_component(self):
        with pytest.raises(ValueError):
            deserialize_proof(
                {
                    "challenge": "1",
                    "nullifier": "1",
                    "components": [{"R": "1", "c": "2"}],  # missing M, s
                }
            )

    def test_deserialize_rejects_empty_components(self):
        with pytest.raises(ValueError):
            deserialize_proof({"challenge": "1", "nullifier": "1", "components": []})


# ---------- input validation ------------------------------------------------


class TestInputValidation:
    def test_prove_rejects_secret_out_of_range(self, small_set, null_base):
        _, pubs = small_set
        with pytest.raises(ValueError):
            prove(0, pubs[0], pubs, "ctx", null_base)
        with pytest.raises(ValueError):
            prove(-1, pubs[0], pubs, "ctx", null_base)
        with pytest.raises(ValueError):
            prove(Q, pubs[0], pubs, "ctx", null_base)

    def test_prove_rejects_public_key_not_in_subgroup(self, small_set, null_base):
        secrets, pubs = small_set
        with pytest.raises(ValueError):
            prove(secrets[0], P - 1, pubs, "ctx", null_base)

    def test_prove_rejects_bad_nullifier_base(self, small_set):
        secrets, pubs = small_set
        with pytest.raises(ValueError):
            prove(secrets[0], pubs[0], pubs, "ctx", P - 1)

    def test_prove_rejects_empty_set(self, small_set, null_base):
        secrets, pubs = small_set
        with pytest.raises(ValueError):
            prove(secrets[0], pubs[0], [], "ctx", null_base)

    def test_verify_rejects_length_mismatch(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        truncated = {
            "challenge": proof["challenge"],
            "nullifier": proof["nullifier"],
            "components": proof["components"][:4],
        }
        with pytest.raises(ProofValidationError):
            verify(truncated, pubs, "ctx", null_base)

    def test_verify_rejects_bad_set_element(self, small_set, null_base):
        secrets, pubs = small_set
        proof = prove(secrets[2], pubs[2], pubs, "ctx", null_base)
        bad_pubs = list(pubs)
        bad_pubs[1] = P - 1  # order-2 element, not in subgroup
        with pytest.raises(ProofValidationError):
            verify(proof, bad_pubs, "ctx", null_base)

    def test_verify_rejects_bad_nullifier_base(self, small_set):
        secrets, pubs = small_set
        nb = nullifier_base_for("DBMS")
        proof = prove(secrets[2], pubs[2], pubs, "ctx", nb)
        with pytest.raises(ProofValidationError):
            verify(proof, pubs, "ctx", P - 1)  # not in subgroup
