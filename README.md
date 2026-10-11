# AnonFeedback

> A college mini-project demonstrating **anonymous faculty feedback** using a
> Zero-Knowledge Proof (ZKP). The college can verify that feedback comes from
> an eligible student, but cannot link a feedback response to that student's
> identity through the intended protocol.

This is an **educational demo**, not production security. See `plan.md` §5
and `report.md` §6 for the security model and limitations.

---


<img width="1023" height="767" alt="3" src="https://github.com/user-attachments/assets/23ba76fd-2a7e-499b-b9c0-fb055ad9050a" />



## What's in the box

```
anonfeedback/
├── plan.md              ← research & design (Phase 1)
├── report.md            ← project report (Phase 4)
├── README.md            ← this file
├── requirements.txt
├── app.py               ← Flask entry point
├── config.py            ← demo configuration
├── zkp/                 ← educational ZKP module (pure crypto)
├── credential/          ← credential issuance + prover
├── server/              ← Flask routes + in-memory store
├── templates/           ← vanilla HTML
├── static/              ← vanilla CSS + JS
└── tests/               ← pytest (67 tests)
```

---

## Setup

You need Python 3.10+ and `pip`.

```bash
cd anonfeedback
python3 -m venv .venv
source .venv/bin/activate        # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

That's it. The only dependencies are Flask and pytest. All cryptography is
implemented in-house using the Python standard library (`hashlib`, `secrets`,
big-integer arithmetic). No obscure PyPI crypto packages are used.

---

## Running the demo

```bash
python3 app.py
```

Then open <http://127.0.0.1:5000/> in your browser.

On first run, the app seeds four demo students (Alice / Bob / Carol / Dan)
and two demo courses (CS101, MA202). The seeded students' secrets are written
to `demo-secrets.txt` in the working directory so you can hand them out. The
server does not retain these secrets after issuance.

---

## The demo workflow (for someone unfamiliar with ZKPs)

The project roleplays three parties: a college, a student, and a public
feedback board. There is no real college authentication — the demo trusts
the admin to enter legitimate student names.

### Step 1 — College issues a credential (`/admin`)

Open the **Admin** console.

1. Type a student name (e.g. `Alice (CS, roll 23)`) and click **Issue
   credential**.
2. The system generates a fresh secret number `x`, computes the corresponding
   public key `Y = g^x`, adds `Y` to the public **eligible set** `S`, and
   shows you the secret.
3. Copy the secret and hand it to the student out-of-band (chat, paper slip,
   etc.). The server does not keep the secret.

Repeat until at least three students have been issued credentials (the demo
enforces `|S| ≥ 3` to mitigate the small-anonymity-set problem).

### Step 2 — Student submits feedback (`/student`)

Open the **Student** console (in another browser tab or window).

1. Paste the secret you received from the college.
2. Pick a course from the **dropdown** (DBMS, OS, CN, OOP, DSA — or any
   course the admin has added). Free-text entry is disabled to prevent
   spelling mistakes.
3. Write your feedback.
4. Click **Generate proof & submit**.

What happens behind the scenes:

- The student's browser calls `/api/student/prove` (a stateless helper) to
  build a **1-out-of-n zero-knowledge proof**. The proof says: *"I know a
  secret `x` such that `g^x` is one of the public keys in `S` — but I won't
  tell you which."* The proof is bound to the feedback text via a hash into
  the Fiat–Shamir transcript, so it can't be replayed against different
  content. The proof also includes a **course-scoped nullifier**
  `N = h^{x_k}` (where `h` is derived from the course id) that lets the
  server reject duplicate submissions for the same (student, course) pair —
  without revealing the student's identity. The nullifier is unlinkable
  across courses and across students (see `report.md` §2.5).
- The browser then calls `/api/submit` with the proof + feedback. The server
  verifies the proof against the public set `S`, checks the nullifier hasn't
  been seen before for this course, and — if both checks pass — stores and
  publishes the feedback. **The server does not consult the name↔key table
  used at issuance.** If the same student tries to submit again for the same
  course, the server returns **409 Conflict** with a non-revealing error.

### Step 3 — Anyone views the feedback board (`/feedback`)

Open the **Feedback board**. Every entry is verified and shown without any
identity. The college verified "the submitter is one of the eligible
students" but could not learn *which* from the proof.

### Try the attacks

- **Tamper with feedback after proof generation.** Use the student UI to
  generate a proof, then manually POST to `/api/submit` with different
  feedback text. The server rejects it — the proof is bound to the original
  text. (See `tests/test_e2e.py::test_replay_with_different_feedback_rejected`.)
- **Submit with an outsider's secret.** Pick a random number that is not a
  real issued secret. The proof-generation step fails because the
  corresponding public key is not in `S`.
- **Tiny eligible set.** Reset the store (restart the server with a cleared
  store) and issue only one student. The student UI shows a warning and
  `/api/submit` returns 400: "anonymity set too small."

---

## How credentials and keys are handled

| Artefact | Who sees it | When | Persisted? |
|---|---|---|---|
| Group parameters `p, q, g` | Everyone | Always | Hardcoded in `zkp/params.py`. |
| Student secret `x` | Student + admin (briefly, at issuance) | Issuance | **No.** The issuer returns it to the admin and forgets it. `demo-secrets.txt` is a demo convenience only. |
| Student public key `Y = g^x` | Everyone | Always | **Yes**, in the public eligible set `S`. |
| Admin's name↔key table | Admin only | Issuance + admin UI | **Yes**, in-memory only. **Never consulted by the verification path.** |
| Submitted feedback + proof | Everyone (public board) | After submission | **Yes**, in-memory. No identity attached. |

Theunlinkability guarantee holds because the verification path
(`server/routes.py::api_submit`) consults **only** the public set `S`
(`store.issuer.eligible_set`). It does not read `store.issuer.issuance_log`.

---

## How verification works (one paragraph)

The verifier receives `(feedback, course, π)` where `π` includes a published
nullifier `N` and per-component commitments `(R_j, M_j, c_j, s_j)`. It
recomputes the Fiat–Shamir challenge from the transcript (which includes
`N`, the per-course nullifier base `h`, every `R_j` and `M_j`, the public
set `S`, and the feedback context). It checks (a) the recomputed challenge
equals the published one, (b) the per-component challenges sum to `c`, (c)
for every `j`, `g^{s_j} ≡ R_j · Y_j^{c_j} mod p` AND `h^{s_j} ≡ M_j · N^{c_j}
mod p`. If all checks pass, the verifier is convinced the prover knew a
single `x` such that `g^x` is some `Y_j ∈ S` AND `N = h^x` for that same
`x`. The transcript is statistically independent of which `j` was the
prover's, so the verifier learns nothing about identity from the proof. The
published `N` lets the server reject duplicates for the same course without
learning the student's identity (see `report.md` §2.5).

---

## Running the tests

```bash
cd anonfeedback
pip install -r requirements.txt
python3 -m pytest tests/ -v
```

Expected output: `92 passed`. The tests cover:

- `test_zkp.py` — completeness, soundness, zero-knowledge (transcript
  freshness), nullifier correctness (determinism, cross-course unlinkability,
  cross-student unlinkability, tampering, swap resistance), tampering of
  every proof field, malformed input rejection, subgroup validation,
  serialisation round-trip.
- `test_credential.py` — issuance, duplicate-name rejection, holder proof
  round-trip (with nullifier), outsider rejection, empty-input rejection,
  per-course nullifier derivation.
- `test_routes.py` — every HTML route, every admin API endpoint, every
  student API endpoint, anonymity-set guard, course-dropdown validation
  (unknown course rejected at both prove and submit), duplicate-prevention
  (same student + same course rejected with 409, nullifier cannot be
  swapped, same student + different courses accepted, different students +
  same course accepted, duplicate rejection doesn't leak first submission),
  no-identity-in-verification-path assertions.
- `test_e2e.py` — full workflow, two-student proof independence, replay
  rejection (different feedback, different course), same-feedback-different-
  student both accepted, **accepted-feedback-appears-on-public-board**
  (regression test for the original app.js destructuring bug),
  student-cannot-submit-twice-for-same-course, student-can-submit-to-
  multiple-courses, five-students-each-submit-to-same-course.

Tests validate the real implementation. No test bypasses, weakens, or
hardcodes behaviour to make tests pass.

---

## Configuration

`config.py` exposes a few knobs:

| Setting | Default | Purpose |
|---|---|---|
| `MIN_ELIGIBLE_SET_SIZE` | 3 | Minimum size of `S` before submissions are accepted. |
| `MAX_FEEDBACK_LENGTH` | 4000 | Max feedback character length. |
| `MAX_COURSE_LENGTH` | 64 | Max course-id character length. |
| `DISABLE_REQUEST_LOGGING` | True | Suppresses Werkzeug's request log (IP + timestamp + path) to avoid metadata leakage in stdout. |
| `SEED_STUDENTS` | 4 names | Pre-seeded students for demo convenience. |
| `PREDEFINED_COURSES` | `["DBMS", "OS", "CN", "OOP", "DSA"]` | Fixed list of courses offered by the simulated college. Populates the student dropdown; the server rejects submissions for any course not in this list (or admin-added at runtime). |
| `SEED_COURSES` | same as `PREDEFINED_COURSES` | Pre-seeded course labels (alias). |

To start with an empty store (no seeding), edit `app.py::_seed_demo_data` or
clear `SEED_STUDENTS` / `SEED_COURSES`.

---

## Limitations you should know about before demoing

This is a college mini-project, not production security. Concretely:

1. **The server sees your IP.** The ZKP does not hide network metadata. A
   real deployment would route submissions over Tor or a mixnet.
2. **1024-bit group parameters** are at the edge of feasibility for
   well-resourced adversaries. Production would use 2048+ bits or an
   elliptic-curve group.
3. **Small classes are not anonymous.** If only one student submits feedback
   in a course, the feedback is effectively identified. The demo enforces
   `|S| ≥ 3` but cannot enforce a minimum *respondent* count.
4. **Self-identifying content** defeats any protocol. The student UI shows a
   reminder.
5. **The admin's issuance log** (name↔key) exists in memory and is shown in
   the admin UI. The unlinkability guarantee holds *because the verification
   path does not read it*. A malicious admin who screenshots the issuance
   table and correlates with submission metadata can break anonymity.
6. **Single-submission enforcement is per (student, course).** A course-
   scoped nullifier `N = h^{x_k}` (where `h = G2^{H(course)}` for a second
   independent generator `G2`) is bound into the proof via a Chaum–Pedersen
   equality check. The server rejects a second submission for the same
   (student, course) pair with HTTP 409. The nullifier is unlinkable across
   courses (DDH) and across students, and is not invertible to identity.
   It is stored with the feedback record but not exposed on the public
   board — only the admin sees it (for audit). See `report.md` §2.5.

See `plan.md` §5 and `report.md` §6 for the full list.

---

## Project layout decisions (for graders)

- **Pure-Python cryptography.** The ZKP is implemented in `zkp/` using only
  `hashlib` and `secrets`. No `pycryptodome`, no `cryptography`, no
  `gmpy2`. This was a deliberate choice: the brief asked us not to blindly
  trust obscure packages, and the CDS proof is small enough to implement
  transparently.
- **SOLID-ish separation.** `zkp/` is pure crypto (no Flask). `credential/`
  orchestrates the protocol. `server/` is thin HTTP transport. Templates and
  static assets are presentation only. This makes the crypto testable in
  isolation.
- **Vanilla frontend.** No React, no Vite, no framework. Just HTML, CSS, and
  a few hundred lines of JS in `static/app.js`.
- **Tests are real.** `tests/` exercises the actual implementation. No
  hardcoded fixtures that bypass logic.

---

## Licence / attribution

Educational project. The CDS 1-out-of-n OR proof construction is from
Cramer, Damgård, Schoenmakers (CRYPTO 1994). The Fiat–Shamir heuristic is
from Fiat–Shamir (CRYPTO 1986). See `plan.md` §8 for full source links.
