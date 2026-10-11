/* AnonFeedback — vanilla JS.
 *
 * No frameworks, no build step. Per-page initialisers are dispatched by
 * detecting which top-level elements exist on the page.
 */

// ---------- tiny helpers ---------------------------------------------------

async function getJSON(url) {
  // Returns the parsed JSON object directly. (The previous version was
  // sometimes destructured as `{ json }`, which silently yielded undefined
  // — that was the root cause of the feedback-board bug.)
  const r = await fetch(url);
  return r.json();
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json() };
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2), v);
    } else {
      node.setAttribute(k, v);
    }
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.appendChild(typeof c === "string" || typeof c === "number"
      ? document.createTextNode(String(c))
      : c);
  }
  return node;
}

function svgIcon(href, cls = "icon") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", cls);
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", href);
  svg.appendChild(use);
  return svg;
}

function shortHash(s, n = 24) {
  return s.length <= n ? s : s.slice(0, n) + "…" + s.slice(-8);
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

// ---------- admin page -----------------------------------------------------

async function refreshAdmin() {
  const [eligible, students, feedback, courses] = await Promise.all([
    getJSON("/api/admin/eligible"),
    getJSON("/api/admin/students"),
    getJSON("/api/admin/feedback"),
    getJSON("/api/admin/courses"),
  ]);

  // eligible count + min required
  const countEl = document.getElementById("eligible-count");
  if (countEl) {
    countEl.textContent = `${eligible.size} eligible`;
  }
  const minEl = document.getElementById("min-required");
  if (minEl) minEl.textContent = String(eligible.min_required);

  // eligible set list
  const setBox = document.getElementById("eligible-set");
  if (setBox) {
    setBox.innerHTML = "";
    if (eligible.size === 0) {
      setBox.appendChild(el("div", { class: "empty",
        style: "padding: var(--space-4); text-align: center;" },
        "No eligible students yet."));
    } else {
      eligible.eligible_set.forEach((y, i) => {
        setBox.appendChild(
          el("div", { class: "eligible-row" },
            el("span", { class: "idx" }, String(i + 1)),
            el("span", { class: "mono" }, y)
          )
        );
      });
    }
  }

  // issuance log table
  const tbody = document.querySelector("#students-table tbody");
  if (tbody) {
    tbody.innerHTML = "";
    if (students.students.length === 0) {
      tbody.appendChild(
        el("tr", {},
          el("td", { colspan: 3, class: "empty" }, "No credentials issued yet.")
        )
      );
    } else {
      for (const s of students.students) {
        tbody.appendChild(
          el("tr", {},
            el("td", {}, s.name),
            el("td", { class: "mono" }, s.student_id),
            el("td", { class: "mono" }, shortHash(s.public_key, 32))
          )
        );
      }
    }
  }

  // courses as chips
  const courseList = document.getElementById("course-list");
  if (courseList) {
    courseList.innerHTML = "";
    if (courses.courses.length === 0) {
      courseList.appendChild(el("span", { class: "empty" }, "No courses yet."));
    } else {
      for (const c of courses.courses) {
        courseList.appendChild(el("span", { class: "chip" }, c));
      }
    }
  }

  // submitted feedback (admin view — includes nullifier)
  const fbList = document.getElementById("admin-feedback-list");
  if (fbList) {
    fbList.innerHTML = "";
    if (feedback.feedback.length === 0) {
      fbList.appendChild(el("div", { class: "empty",
        style: "padding: var(--space-3);" },
        "No feedback submitted yet."));
    } else {
      for (const f of feedback.feedback) {
        fbList.appendChild(renderFeedbackItem(f, { showNullifier: true }));
      }
    }
  }
}

function setupAdminForms() {
  const issueForm = document.getElementById("issue-form");
  if (issueForm) {
    issueForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = issueForm.elements["name"].value;
      const box = document.getElementById("issue-result");
      box.hidden = false;
      box.className = "result";
      box.textContent = "Issuing…";
      const { json } = await postJSON("/api/admin/issue", { name });
      if (json.ok) {
        const r = json.result;
        box.className = "result ok";
        box.textContent =
          `Issued credential for ${r.name}.\n` +
          `student_id: ${r.student_id}\n` +
          `public_key (Y): ${r.public_key}\n\n` +
          `secret (x) — HAND THIS TO THE STUDENT OUT-OF-BAND:\n${r.secret}\n\n` +
          `The server does not retain this secret. Copy it now.`;
        issueForm.reset();
        refreshAdmin();
      } else {
        box.className = "result err";
        box.textContent = `Error: ${json.error}`;
      }
    });
  }

  const courseForm = document.getElementById("course-form");
  if (courseForm) {
    courseForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const course = courseForm.elements["course"].value;
      const { json } = await postJSON("/api/admin/course", { course });
      if (!json.ok) {
        alert(`Error: ${json.error}`);
        return;
      }
      courseForm.reset();
      refreshAdmin();
      // also refresh the student dropdown if we're on the same page (we're not, but cheap)
    });
  }
}

// ---------- student page ---------------------------------------------------

async function refreshStudent() {
  const [eligible, courses] = await Promise.all([
    getJSON("/api/admin/eligible"),
    getJSON("/api/admin/courses"),
  ]);

  const sizeEl = document.getElementById("eligible-size");
  if (sizeEl) sizeEl.textContent = String(eligible.size);
  const minEl = document.getElementById("min-required");
  if (minEl) minEl.textContent = String(eligible.min_required);

  // populate course dropdown
  const sel = document.getElementById("course-select");
  if (sel) {
    // preserve current selection if any
    const cur = sel.value;
    sel.innerHTML = "";
    sel.appendChild(el("option", { value: "", disabled: true },
      "Pick a course…"));
    for (const c of courses.courses) {
      const opt = el("option", { value: c }, c);
      if (c === cur) opt.selected = true;
      sel.appendChild(opt);
    }
  }

  // eligibility badge + note
  const badge = document.getElementById("eligibility-badge");
  const note = document.getElementById("eligibility-note");
  if (badge && note) {
    badge.className = "badge";
    note.innerHTML = "";
    if (eligible.size < eligible.min_required) {
      badge.classList.add("badge--warning");
      badge.textContent = "Too small";
      note.appendChild(el("div", { class: "callout callout--warning" },
        svgIcon("#i-warn", "icon callout__icon"),
        el("div", {},
          `Anonymity set too small: only ${eligible.size} eligible student(s). ` +
          `At least ${eligible.min_required} are required before feedback can be submitted. ` +
          `Issue more credentials in the Admin console.`
        )
      ));
    } else {
      badge.classList.add("badge--success");
      badge.textContent = "OK";
    }
  }
}

function setupStudentForm() {
  const form = document.getElementById("feedback-form");
  if (!form) return;

  // character count
  const fb = form.elements["feedback"];
  const count = document.getElementById("char-count");
  if (fb && count) {
    const update = () => {
      const n = fb.value.length;
      count.textContent = `${n} / 4000 characters`;
      count.style.color = n > 3800 ? "var(--color-danger)" : "";
    };
    fb.addEventListener("input", update);
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const secret = form.elements["secret"].value.trim();
    const course = form.elements["course"].value;
    const feedback = form.elements["feedback"].value;
    const box = document.getElementById("submit-result");
    box.hidden = false;
    box.className = "result";
    box.textContent = "Generating proof…";

    if (!course) {
      box.className = "result err";
      box.textContent = "Please pick a course from the dropdown.";
      return;
    }

    // 1. Ask the server to build the proof (stateless helper).
    const proveRes = await postJSON("/api/student/prove", {
      secret, feedback, course,
    });
    if (!proveRes.json.ok) {
      box.className = "result err";
      box.textContent = `Proof generation failed: ${proveRes.json.error}`;
      return;
    }

    box.textContent = "Proof generated. Verifying & submitting…";

    // 2. Submit proof + feedback for verification.
    const submitRes = await postJSON("/api/submit", {
      feedback: proveRes.json.feedback,
      course: proveRes.json.course,
      proof: proveRes.json.proof,
    });
    if (!submitRes.json.ok) {
      box.className = "result err";
      box.textContent = `Submission rejected: ${submitRes.json.error}`;
      return;
    }

    box.className = "result ok";
    box.textContent =
      `Feedback submitted and verified.\n` +
      `The college verified that you are an eligible student, but the proof ` +
      `transcript does not reveal which one. Your feedback is now on the ` +
      `public feedback board. You cannot submit again for ${course}.`;
    form.reset();
    if (count) count.textContent = "0 / 4000 characters";
  });
}

// ---------- feedback board -------------------------------------------------

function renderFeedbackItem(f, opts = {}) {
  const meta = el("div", { class: "meta" },
    el("span", { class: "course" }, f.course),
    el("span", {}, fmtTime(f.timestamp))
  );
  if (opts.showNullifier && f.nullifier) {
    meta.appendChild(
      el("span", { class: "badge badge--mono", title: "Per-course pseudonym (unlinkable)" },
        "N: " + shortHash(f.nullifier, 16))
    );
  }
  return el("div", { class: "feedback-item" },
    meta,
    el("div", { class: "body" }, f.feedback),
    el("div", { class: "verified" },
      svgIcon("#i-check", "icon"),
      `verified against the eligible set · ${f.proof_components} components`
    )
  );
}

async function refreshFeedbackBoard() {
  const list = document.getElementById("feedback-list");
  if (!list) return;
  list.innerHTML = "";

  const countBadge = document.getElementById("board-count");

  // getJSON() returns the parsed JSON object directly (NOT {status, json}).
  // The previous version destructured `json` from it, which yielded undefined
  // and silently aborted the render — the feedback-board bug.
  const json = await getJSON("/api/feedback");
  if (!json || !json.ok || !Array.isArray(json.feedback) || json.feedback.length === 0) {
    list.appendChild(el("div", { class: "card empty",
      style: "text-align: center; padding: var(--space-8);" },
      "No feedback submitted yet."
    ));
    if (countBadge) countBadge.textContent = "0 entries";
    return;
  }

  for (const f of json.feedback) {
    list.appendChild(renderFeedbackItem(f));
  }
  if (countBadge) {
    const n = json.feedback.length;
    countBadge.textContent = `${n} ${n === 1 ? "entry" : "entries"}`;
  }
}

function setupFeedbackBoard() {
  const btn = document.getElementById("refresh-btn");
  if (btn) btn.addEventListener("click", refreshFeedbackBoard);
}

// ---------- bootstrap ------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  setupAdminForms();
  setupStudentForm();
  setupFeedbackBoard();

  // refresh whichever page we're on
  if (document.getElementById("students-table")) refreshAdmin();
  if (document.getElementById("feedback-form")) refreshStudent();
  if (document.getElementById("feedback-list")) refreshFeedbackBoard();
});
