# AnonFeedback — Research & Implementation Plan

> Phase 1 deliverable. This document records the research, design decisions,
> architecture, security model, and implementation plan for the AnonFeedback
> college mini-project: an anonymous faculty-feedback demonstrator built around
> Zero-Knowledge Proofs (ZKPs).

---

## 1. Problem Statement

College faculty feedback systems today (Google Forms, Microsoft Forms, physical
paper forms) face a structural trust problem:

- **Google Forms / Microsoft Forms**: When run by an institution account, the
  form owner can silently enable email collection, view respondent timestamps,
  and correlate responses with login sessions. Even when the institution
  *promises* "responses are anonymous," students have no technical guarantee.
  They must trust the platform and the form owner.
- **Physical paper forms**: Anonymity depends on physical handling (no names on
  paper, shuffled collection box). This is hard to audit and breaks down at
  scale or when the class is small enough that handwriting or content gives the
  student away.
- **Identified online forms**: Asking students to sign in lets the college
  verify eligibility (each respondent is a real student), but every response is
  permanently tied to an identity in the backend.

The core tension is **eligibility verification vs. response anonymity**. The
college wants to reject feedback from non-students (spam, manipulation,
external actors); students want a *technical* (not merely policy-based)
guarantee that their feedback cannot be traced back to them.

AnonFeedback explores whether **Zero-Knowledge Proofs** can resolve this
tension: the college verifies that *some* eligible student produced the
feedback, but the protocol itself does not reveal *which* one.

**Scope.** This is a college mini-project and demonstrator. It is **not**
production-ready, not hardened against a determined deanonymization adversary,
and not a substitute for a formally audited anonymous-feedback system. The goal
is to make the cryptographic workflow concrete, runnable, and understandable.

---

## 2. Research: ZKP Approaches for Anonymous Credentials

### 2.1 What property do we actually need?

We need a proof with three cryptographic properties:

1. **Completeness** — an honest eligible student can always produce a proof that
   the college accepts.
2. **Soundness** — a non-eligible party (someone whose key is not in the
   eligible set) cannot produce an accepting proof, except with negligible
   probability.
3. **Zero-knowledge (unlinkability)** — the proof reveals nothing about *which*
   eligible student produced it. In particular, two proofs from the same student
   are computationally indistinguishable from two proofs by different students.

### 2.2 Candidate constructions surveyed

| Approach | Description | Verdict for this project |
|---|---|---|
| **zk-SNARKs** (e.g., `py-circom`, `snarkjs` via bindings) | Succinct non-interactive arguments; require a trusted setup or universal SRS, circuit compiler, pairing-friendly curves. | Overkill and heavyweight. Tooling is fragile, setups are non-trivial, and the cryptographic core would be a black box — defeating the educational goal. |
| **Bulletproofs** | Short aggregatable range/set-membership proofs; no trusted setup. | Implementation complexity is high; the educational message gets lost in inner-product arguments. |
| **Anonymous credentials (Idemix, BBS+)** | Mature credential frameworks with selective disclosure and unlinkable presentation. | `pycryptosdk`/Idemix Python ports are largely unmaintained or research-grade. BBS+ requires pairing curves. Too much surface area for a mini-project. |
| **Ring signatures** (e.g.,MLSAG / Linkable Ring Signature as in Monero) | Signer proves membership in a set of public keys; signature reveals nothing about which. | Strong match conceptually. A 1-out-of-n ring signature *is* essentially a non-interactive OR-proof. |
| **1-out-of-n OR Sigma protocol (Cramer–Damgård–Schoenmakers, CDS)** | Disjunctive ZKP: prove "I know the discrete log of **one of** {Y_1,…,Y_n}" without revealing which. Made non-interactive via Fiat–Shamir. | **Best fit.** Small, transparent, implementable from first principles in pure Python, and demonstrates the ZKP idea crisply. |

### 2.3 Selected construction: CDS 1-out-of-n OR proof

We implement the classic **CDS 1-out-of-n disjunctive proof of set membership**
in a prime-order group, made non-interactive with the Fiat–Shamir heuristic.

**Why this choice:**

- It is a *real* ZKP construction documented in the cryptography literature
  (Cramer, Damgård, Schoenmakers, "Proofs of Partial Knowledge", CRYPTO 1994).
- It is small enough to implement in ~150 lines of transparent Python using
  only `hashlib` and big-integer arithmetic — every step is inspectable.
- It demonstrates the three ZKP properties (completeness, soundness, ZK) in a
  form a student can reason about.
- It maps directly onto our problem: the eligible set is the set of registered
  student public keys; the student proves knowledge of the discrete log of one
  of them without revealing which.

### 2.4 Python library evaluation

We deliberately minimise third-party dependencies and avoid obscure /
unmaintained packages.

| Library | Role | Provenance / maintenance | Decision |
|---|---|---|---|
| `flask` | Web framework | Pallets project; very widely used; active maintenance. | **Use.** |
| `hashlib` (stdlib) | Fiat–Shamir transcript hashing | Python standard library; SHA-256 is FIPS-validated. | **Use.** |
| `secrets` (stdlib) | Cryptographic randomness | Python standard library; wraps OS CSPRNG. | **Use.** |
| `pytest` | Test runner | Well-maintained, standard. | **Use.** |
| `pycryptodome` | Optional crypto primitives | Actively maintained, packaged by most distros. | **Not needed** — we use stdlib big ints + hashlib. Avoiding it removes one dependency surface. |
| `cryptography` | Optional crypto primitives | pyca, well-maintained. | **Not needed** for the same reason. |
| `gmpy2` | Fast modular exponentiation | Optional C accelerator. | **Not used** to keep install trivial. Python's native `pow(a, b, m)` uses an efficient C implementation internally. |
| Various ZKP-specific PyPI packages (`pyzk`, `zkp`, `petlib`, etc.) | Pre-built ZKP | Mostly abandoned research code, last commits years ago, sparse docs. | **Rejected.** Per the brief, we do not blindly trust obscure packages. |

**Conclusion:** the project uses **Flask + Python standard library only**, plus
pytest for tests. The ZKP is implemented in-house as an educational module with
clearly documented scope and limitations.

### 2.5 Is a custom educational ZKP module necessary?

**Yes.** No mature, well-maintained, general-purpose Python library exposes a
clean 1-out-of-n OR proof suitable for this demo without pulling in heavy
machinery (pairing curves, R1CS compilers, etc.). Implementing the CDS proof
directly is:

- *Educationally valuable* — every step is inspectable.
- *Auditable in ~150 lines* — small enough to reason about formally.
- *Honest about its scope* — we document exactly what it does and does not
  guarantee, rather than wrapping it in marketing language.

The module's scope and limitations are listed in §5 and inside `zkp/or_proof.py`.

---

## 3. Cryptographic Design

### 3.1 Group setup

- `p` — a 1024-bit safe prime (`p = 2q + 1`, both `p` and `q` prime).
- `q` — the prime `(p-1)/2`; the subgroup of quadratic residues mod `p` has
  order `q`.
- `g` — a generator of the order-`q` subgroup, computed as `h^2 mod p` for a
  random `h` (so `g != 1` and `g^q ≡ 1 mod p`).

These parameters are generated once (see `scripts/generate_safe_prime.py`) and
hardcoded in `zkp/params.py`. **1024 bits is a demo compromise** for generation
speed; production systems would use 2048+ bits. The discrete-log problem in
this group at 1024 bits is at the boundary of feasibility for nation-state
adversaries and must not be relied upon for real secrets.

### 3.2 Credential model

For the demo we roleplay four parties:

| Party | Role | Holds |
|---|---|---|
| **College (Admin)** | Issues credentials, verifies proofs, stores feedback. | Eligible-set `S = {Y_1,…,Y_n}` (public keys). Master list of names↔public keys (only used at issuance time, **not** at verification). |
| **Student** | Generates a secret, registers the public key, later proves membership and submits feedback. | Secret scalar `x_i`, public key `Y_i = g^{x_i} mod p`. |
| **Verifier (College, verification mode)** | Checks a submitted proof against the current eligible set. | The public eligible set `S`. **Not** the master name↔key table. |
| **Public feedback board** | Anyone may read verified feedback. | Feedback text + proof + verification result. |

**Issuance flow (simulated):**

1. Admin opens the admin console and enters a student name (e.g., "Alice / CS
   dept / roll 23"). This name exists **only** in the admin's private issuance
   table for the duration of the demo; it is never stored alongside feedback.
2. The system generates a fresh secret `x_i ∈ Z_q`, computes `Y_i = g^{x_i}`,
   and adds `Y_i` to the public eligible set `S`.
3. The system returns `x_i` to the admin, who is instructed (in the UI and
   README) to hand it to the student via a simulated out-of-band channel (e.g.,
   paste into a chat). The secret is **not** persisted server-side after
   issuance — only `Y_i` is.

In a real deployment, step 3 would use a proper credential protocol (e.g.,
blind signature or Idemix) so the college never sees `x_i`. For the demo we
simplify: the college *does* briefly see `x_i` at issuance, but **never at
verification**. Theunlinkability property we actually demonstrate holds at
verification time, which is the relevant moment.

### 3.3 Proof: 1-out-of-n OR proof of set membership

A student holding `x_k` with `Y_k = g^{x_k}` produces, for the current eligible
set `S = {Y_1,…,Y_n}`:

For each `j ≠ k` (simulated components):
- Pick random `c_j, s_j ∈ Z_q`.
- Compute `R_j = g^{s_j} · Y_j^{-c_j} mod p`.

For the real index `k`:
- Pick random `r_k ∈ Z_q`.
- Compute `R_k = g^{r_k} mod p`.

Combine via Fiat–Shamir:
- `c = H( "anonfeedback.v1" ‖ R_1 ‖ … ‖ R_n ‖ S ‖ feedback_commitment )`
- `c_k = c − Σ_{j≠k} c_j mod q`
- `s_k = r_k + c_k · x_k mod q`

The published proof is `π = ((R_1, s_1, c_1), …, (R_n, s_n, c_n))` (one tuple
per member of the eligible set), plus the overall challenge `c` for fast
verification.

**Verification:**
- Recompute `c' = H( "anonfeedback.v1" ‖ R_1 ‖ … ‖ R_n ‖ S ‖ feedback_commitment )`
  and check `c' == c`.
- Check `Σ_j c_j ≡ c mod q`.
- For each `j`, check `g^{s_j} · Y_j^{-c_j} ≡ R_j mod p`.

If all checks pass, the verifier is convinced that the prover knows the discrete
log of *some* `Y_j ∈ S`, but the distribution of `(R_j, s_j, c_j)` is uniform
and independent of `k`, so the proof reveals nothing about which.

### 3.4 What binds the proof to the feedback?

The Fiat–Shamir transcript includes a **feedback commitment**
`H("feedback" ‖ feedback_text ‖ course_id)`. This makes the proof bound to a
specific feedback payload — it cannot be replayed against different content or
course. (Replay of the *exact same* payload is discussed under limitations.)

### 3.5 End-to-end flow

```
 ┌─────────┐   (1) issue: name ──►  ┌─────────┐
 │ Admin   │  ◄── (2) secret x_i,   │ System  │  adds Y_i=g^x_i to S
 │ console │       pub key Y_i      │         │
 └─────────┘                         └─────────┘
     │ (3) admin hands x_i to student out-of-band (roleplay)
     ▼
 ┌─────────┐   (4) POST /api/submit { feedback, course, proof π }
 │ Student │  ◄── (5) 200 OK or 4xx with reason
 │ console │
 └─────────┘
                 (6) Server verifies π against current S
                     (S includes ALL eligible Y_i, never the name table)
                 (7) If valid → store {feedback, course, π, timestamp, nullifier-tag}
                     Publish to /feedback board (anonymous)
```

The critical property: **at step (6), the verifier only consults `S`, the public
set of public keys.** The name↔key table used at step (1) is not consulted and
plays no role in verification or storage.

---

## 4. System Architecture

```
anonfeedback/
├── plan.md                  ← this file
├── report.md                ← Phase 4 project report
├── README.md                ← setup & usage
├── requirements.txt
├── app.py                   ← Flask entry point
├── config.py                ← demo configuration
│
├── zkp/                     ← educational ZKP module
│   ├── __init__.py
│   ├── params.py            ← safe prime p, q, generator g (hardcoded)
│   ├── group.py             ← helpers: rand scalar, modexp, hashing-to-scalar
│   └── or_proof.py          ← CDS 1-out-of-n OR proof (prove + verify)
│
├── credential/              ← credential / issuance layer
│   ├── __init__.py
│   ├── issuer.py            ← college-side: issue credential, manage eligible set
│   └── holder.py            ← student-side: build proof for a given feedback
│
├── server/                  ← Flask app
│   ├── __init__.py
│   ├── store.py             ← in-memory store (eligible set, feedback, audit)
│   └── routes.py            ← HTML routes + JSON API
│
├── templates/               ← vanilla HTML (Jinja2 templates, no framework)
│   ├── base.html
│   ├── index.html
│   ├── admin.html
│   ├── student.html
│   └── feedback.html
│
├── static/                  ← vanilla CSS + JS
│   ├── style.css
│   └── app.js
│
└── tests/                   ← pytest
    ├── conftest.py
    ├── test_zkp.py
    ├── test_credential.py
    ├── test_routes.py
    └── test_e2e.py
```

### 4.1 Module responsibilities (SOLID)

- `zkp/` — pure cryptography. No Flask, no I/O. Testable in isolation.
- `credential/` — orchestrates the protocol on top of `zkp/`. Knows about
  "students" and "eligible sets" but not about HTTP.
- `server/` — HTTP transport. Thin: parse JSON, delegate to `credential/`,
  render templates. No crypto logic here.
- `templates/` + `static/` — presentation only.

### 4.2 Flask routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Landing page (links to admin / student / feedback). |
| GET | `/admin` | Admin console: issue credential, view eligible set, view submitted feedback. |
| POST | `/api/admin/issue` | Issue a credential for a student name. Returns `{student_id, secret, public_key}`. |
| GET | `/api/admin/eligible` | JSON list of currently-eligible public keys (the set `S`). |
| GET | `/api/admin/feedback` | JSON list of submitted feedback (text, course, timestamp, verification status). **No identity.** |
| GET | `/student` | Student console: enter secret, view eligible set, write feedback, generate proof, submit. |
| POST | `/api/student/prove` | Server-side helper *only for the demo UI* — given `{secret, feedback, course}`, builds the proof client-side-equivalent and returns it. (See note below.) |
| POST | `/api/submit` | Submit feedback + proof. Verifies and stores. |
| GET | `/feedback` | Public feedback board. |
| GET | `/api/feedback` | JSON of verified feedback. |

> **Note on `/api/student/prove`:** In a "real" deployment the student would
> generate the proof entirely client-side in JS. For an educational Python demo,
> we provide a server endpoint that runs the same `credential.holder` code so
> the student UI can stay in vanilla JS without re-implementing big-integer
> math in the browser. The endpoint does **not** store the secret or the
> feedback; it is a stateless helper. The brief explicitly allows a "carefully
> implemented educational module," and keeping the crypto in auditable Python
> (rather than 1000 lines of JS BigInt) is the cleaner choice. We document this
> clearly in `report.md`.

---

## 5. Security Model, Assumptions, Limitations

We are precise about what is a *cryptographic guarantee* and what is an
*assumption* or *limitation*.

### 5.1 Cryptographic guarantees (under the stated assumptions)

1. **Completeness.** An honest student who knows a valid `x_k` with `Y_k ∈ S`
   will produce a proof accepted by the verifier, with probability 1.
2. **Soundness.** A party who does *not* know any discrete log of any `Y_j ∈ S`
   cannot produce an accepting proof, except with probability ≤ 2^{−λ} where λ
   is the security parameter of the hash (256-bit for SHA-256). Relies on the
   discrete-log hardness assumption in the order-`q` subgroup and the
   random-oracle model for Fiat–Shamir.
3. **Honest-verifier zero-knowledge / unlinkability of the proof object.** The
   distribution of `π` is statistically independent of the prover's index `k`.
   Two proofs from the same student are computationally indistinguishable from
   two proofs by different students. This is a property of the *proof transcript
   itself*.

### 5.2 Assumptions

- A1. The discrete logarithm problem in the chosen subgroup is intractable for
  the adversary class we care about (educational threat model). At 1024 bits
  this is borderline; see §5.3.
- A2. SHA-256 behaves as a random oracle (Fiat–Shamir heuristic).
- A3. The admin's issuance table (name ↔ public key) is not consulted at
  verification time and is not leaked. Theunlinkability guarantee is broken if
  the admin inspects the issuance table alongside submitted proofs and the
  eligible set is small enough to permit correlation by elimination (see §5.4).
- A4. `secrets` (OS CSPRNG) is secure.
- A5. The transport between admin and student for handing over `x_i` is
  out-of-band and not observed by the server. (In the demo we roleplay this; the
  server's `/api/admin/issue` returns the secret to the admin's browser, which
  the admin then pastes to the student.)
- A6. The server does not keep per-request logs that include `x_i`. (The demo's
  `server/store.py` deliberately does not persist secrets.)

### 5.3 Limitations (NOT solved by the ZKP)

- **L1 — Parameter size.** We use a 1024-bit safe prime for generation speed.
  1024-bit finite-field discrete log is at the edge of feasibility for
  well-resourced adversaries (cf. the Logjam paper and ongoing 1024-bit DH
  precomputation concerns). A real deployment would use 2048+ bits or, better,
  an elliptic-curve group of order ~2^256.
- **L2 — IP tracking.** The Flask server sees the submitter's IP address. The
  ZKP does not hide network metadata. In a real deployment, students would
  submit over Tor or an anonymizing mixnet. **The demo does not anonymize
  network traffic.**
- **L3 — Timing correlation.** If the admin records "Alice was issued a
  credential at 14:03:11" and "a feedback arrived at 14:04:52 from IP X," and
  Alice's machine is the one with IP X, the proof'sunlinkability is defeated by
  metadata. The ZKP only protects the *cryptographic* link, not traffic
  analysis.
- **L4 — Small eligible sets.** If `|S| = 1`, the proof trivially identifies
  the student. If `|S| = 2` and only one student submits, anonymity reduces to
  a 1-bit guess. This is the **small-anonymity-set** problem and is fundamental.
  The demo requires `|S| ≥ 3` before accepting submissions, with a clear UI
  warning.
- **L5 — Small respondent groups.** Even with a large `S`, if only one student
  submits feedback in a course, the feedback is effectively identified (the
  college knows which student(s) didn't submit, narrowing it down). The demo
  documents this but cannot prevent it.
- **L6 — Identifying content.** A student who writes "I'm the only one who got
  an A+ in your course and I thought the lectures were great" has identified
  themselves. **No cryptographic protocol can prevent this.** The UI shows a
  reminder.
- **L7 — Duplicate submissions (now mitigated by a nullifier).** Earlier
  versions of this demo accepted that two identical feedback payloads produce
  two different valid proofs, and that the server could not cryptographically
  tell they came from the same student. The current version implements a
  **course-scoped nullifier** `N = h^{x_k}` where `h = G2^{H(course)}` is a
  per-course base derived from a second independent generator `G2` (whose DL
  with respect to `G` is unknown — see `zkp.group.hash_to_subgroup`). The
  proof is extended with a Chaum–Pedersen equality proof that ties `N` to the
  same `x_k` whose knowledge of `Y_k = g^{x_k}` is proved, so a malicious
  student cannot lie about `N` to bypass dedup. The nullifier is:

  * **Deterministic in (student_secret, course)** → the server can reject a
    second submission for the same (student, course) pair (HTTP 409 Conflict).
  * **Unlinkable across courses** → `h` differs per course; under DDH, `N`
    for DBMS and `N` for OS by the same student are pseudorandom and
    unlinkable.
  * **Unlinkable across students** → different `x_k` give different `N`.
  * **Not invertible to identity** → the server cannot test `N` against each
    `Y_j` to recover `k`, because that would require knowing `log_g(h)`,
    which is unknown.

  The nullifier IS stored with the feedback record (for dedup) but is NOT
  exposed on the public board — only the admin sees it (for audit) via
  `FeedbackRecord.admin_dict`. The nullifier is NOT a student identifier.

  Residual limitation: the nullifier does not prevent a determined adversary
  who *re-issues* a credential (e.g. asks the admin for a second secret under
  a different name) from submitting twice. That is an issuance-side problem,
  not a proof-side one, and is out of scope.
- **L8 — Server-side logging.** Default Flask / WSGI servers log request lines
  (IP, timestamp, path). The demo disables request logging in `app.py` and
  documents that any reverse proxy in front must be configured similarly.
- **L9 — Single-server trust.** All state lives in one Flask process. A
  compromised server can DoS the system, reject valid proofs, or alter stored
  feedback. It cannot, however, learn the prover's identity from a valid proof
  transcript alone (assuming A3 holds and the server doesn't correlate via
  metadata, which L2/L3 already concede).
- **L10 — No formal proof.** The CDS construction is well-studied, but our
  implementation has not been formally verified. We rely on tests + code review.

### 5.4 Edge cases the implementation must handle

- Submitting with a secret whose public key is *not* in `S` → proof must fail.
- Submitting with a malformed proof (wrong length, non-integer fields,
  Σc_j ≠ c, failed subgroup check) → 400 Bad Request with a generic reason.
- Submitting to a course with `|S| < 3` → 400 with a clear message.
- Tampering with the feedback after proof generation → verification fails
  (because the Fiat–Shamir transcript binds to `H(feedback)`).
- Replaying an old proof against new eligible set → fails (set is part of
  transcript).
- Empty feedback / missing course / missing proof → 400.

---

## 6. Demonstrating Without a Real College Auth System

We roleplay:

- **The college** is the admin console. The "registrar" is whoever has access
  to `/admin`. There is no real SSO; the demo trusts the admin to enter
  legitimate student names.
- **Students** are simulated by anyone with the `/student` URL and a secret.
- The "issuance channel" is copy-paste: admin clicks "Issue," gets a secret,
  and is told to paste it to the student via any out-of-band channel (chat,
  email, paper slip).
- A "course" is a label from a predefined dropdown: **DBMS, OS, CN, OOP, DSA**
  (Indian college subjects). The admin can add more via the admin console;
  students pick from a `<select>` populated from the server — no free-text
  entry, no spelling mistakes. The server independently rejects submissions
  for unknown courses via `_require_known_course`.
- The demo seeds 4 example students and 5 example courses on first run so
  the small-set guard (L4) doesn't block immediate experimentation.

This is clearly labelled as roleplay in the UI and README.

---

## 7. Implementation Plan (Phase 2 onward)

1. **ZKP module (`zkp/`)**
   - `params.py`: hardcoded 1024-bit safe prime, `q`, generator `g`.
   - `group.py`: `rand_scalar()`, `modexp()`, `hash_to_scalar()`, serialisation
     helpers.
   - `or_proof.py`: `prove(secret, public_key, set_S, context) → π`,
     `verify(π, set_S, context) → bool`. Include a `ProofValidationError`
     exception with a `reason` field for the server to surface.
2. **Credential module (`credential/`)**
   - `issuer.py`: `IssueCredential(name) → (student_id, secret, public_key)`;
     manages `S` and the issuance table (in-memory).
   - `holder.py`: `build_proof(secret, feedback, course, S) → π`. Thin wrapper
     over `zkp.or_proof.prove`.
3. **Server (`server/`)**
   - `store.py`: in-memory singleton holding `S`, issuance table (name→Y),
     feedback list.
   - `routes.py`: routes from §4.2. Input validation, error handling, no
     crypto logic.
   - `app.py`: create Flask app, register routes, disable request logging.
4. **Frontend (`templates/`, `static/`)**
   - Google-Forms-style: simple cards, labels, text inputs, textareas, a
     submit button. Vanilla JS for the proof/submit round-trip.
5. **Tests (`tests/`)**
   - `test_zkp.py`: completeness, soundness (random invalid secret rejected),
     ZK (two proofs by same prover are distributed independently — sanity
     check that transcripts differ), tampered context rejected, malformed
     proofs rejected.
   - `test_credential.py`: issuance produces a key in `S`; holder builds an
     accepting proof; wrong-secret rejection.
   - `test_routes.py`: all GET routes return 200; `/api/submit` accepts valid,
     rejects invalid; small-set guard; missing fields.
   - `test_e2e.py`: issue 4 students → each submits feedback → all verified →
     feedback board shows them anonymously → identity table is not consulted
     by the verification path (assert via internal API).
6. **Documentation**: `report.md`, `README.md`.
7. **Packaging**: ZIP the whole project into `download/anonfeedback.zip`.

---

## 8. Sources

- Cramer, Damgård, Schoenmakers. *Proofs of Partial Knowledge and Simplified
  Design of Witness Hiding Protocols.* CRYPTO 1994.
  <https://link.springer.com/chapter/10.1007/3-540-48658-5_19>
- Fiat, Shamir. *How to Prove Yourself: Practical Solutions to Identification
  and Signature Problems.* CRYPTO 1986.
- Schnorr. *Efficient Signature Generation by Smart Cards.* J. Cryptology 1991.
- Bellare, Rogaway. *Random Oracles are Practical.* CCS 1993 (Fiat–Shamir
  methodology).
- Adrian et al. *Imperfect Forward Secrecy: How Diffie-Hellman Fails in
  Practice (Logjam).* CCS 2015. <https://weakdh.org/>
- CDS-style OR proofs, expository notes:
  <https://en.wikipedia.org/wiki/Zero-knowledge_proof#Disjunctive_and_conjunctive_proofs>
  and Boneh–Shoup *Graduate Course in Applied Cryptography*, ch. 19–20
  (<https://toc.cryptobook.us/>).
- Flask documentation: <https://flask.palletsprojects.com/>
- Python `hashlib` / `secrets` standard library docs:
  <https://docs.python.org/3/library/hashlib.html>,
  <https://docs.python.org/3/library/secrets.html>
