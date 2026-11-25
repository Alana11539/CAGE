"""Build the Computers & Security manuscript as an editable Word file.

    python scripts/build_manuscript.py

The builder reads real repository values - the frozen configuration, the
policy version, the case-set counts and the verified reference list - and
writes ``manuscript/CAGE_Computers_and_Security_Manuscript.docx``.

It never invents a result. While the configuration gate is closed the Results
section is written as an explicit PENDING section with the table skeletons the
exports will fill, and the abstract carries a marked placeholder instead of a
findings sentence. Running the builder after the gate opens and the exports
exist is what turns those into text.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

OUT = REPO_ROOT / "manuscript" / "CAGE_Computers_and_Security_Manuscript.docx"
GRAPHICAL_ABSTRACT = REPO_ROOT / "docs" / "graphical_abstract.png"
ARCHITECTURE = REPO_ROOT / "docs" / "architecture.png"

TITLE = ("Ask, Allow, or Block: Runtime Enforcement with Human Confirmation "
         "Against Indirect Prompt Injection in Tool-Calling LLM Agents")
SUBTITLE = "CAGE (Composition-Aware Guard Evaluation for Agentic AI)"
AUTHORS = ["Farkha Alana Gul", "Marwah Saleh", "Eman Razzaq", "Dr. Ahmad Mustafa"]
AFFILIATION = ("Department of Software Engineering, Faculty of Computing & Information "
               "Technology")

HIGHLIGHTS = [
    "Runtime guard returns allow, block or ask for every agent tool call",
    "Delegated parameters from user-named sources route to human confirmation",
    "Origin checks alone cannot separate injected from legitimate payees",
    "Security and usability metrics are always reported as a paired set",
    "Guard, harness, case set and console released for independent reuse",
]

KEYWORDS = ["LLM agent security", "indirect prompt injection", "runtime enforcement",
            "reference monitor", "human-in-the-loop authorisation", "security-usability trade-off"]

PENDING = "PENDING"


# ---------------------------------------------------------------- helpers
def add_line_numbers(section) -> None:
    """Continuous line numbering, as Elsevier requests for review copies."""
    ln = OxmlElement("w:lnNumType")
    ln.set(qn("w:countBy"), "1")
    ln.set(qn("w:restart"), "continuous")
    ln.set(qn("w:distance"), "360")
    section._sectPr.append(ln)


def add_page_numbers(section) -> None:
    para = section.footer.paragraphs[0]
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = para.add_run()
    for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
        if kind:
            fld = OxmlElement("w:fldChar")
            fld.set(qn("w:fldCharType"), kind)
            run._r.append(fld)
        else:
            instr = OxmlElement("w:instrText")
            instr.set(qn("xml:space"), "preserve")
            instr.text = f" {text} "
            run._r.append(instr)


def style_document(doc: Document) -> None:
    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal.font.size = Pt(12)
    pf = normal.paragraph_format
    pf.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    pf.space_after = Pt(6)
    for name, size, bold in (("Heading 1", 14, True), ("Heading 2", 12.5, True),
                             ("Heading 3", 12, True)):
        st = doc.styles[name]
        st.font.name = "Times New Roman"
        st.font.size = Pt(size)
        st.font.bold = bold
        st.font.color.rgb = RGBColor(0x00, 0x00, 0x00)
    for s in doc.sections:
        s.left_margin = s.right_margin = Inches(1.0)
        s.top_margin = s.bottom_margin = Inches(1.0)
        add_line_numbers(s)
        add_page_numbers(s)


def para(doc, text, *, style=None, align=None, italic=False, bold=False, size=None,
         space_after=None):
    p = doc.add_paragraph(style=style)
    run = p.add_run(text)
    run.italic = italic
    run.bold = bold
    if size:
        run.font.size = Pt(size)
    if align:
        p.alignment = align
    if space_after is not None:
        p.paragraph_format.space_after = Pt(space_after)
    return p


def pending_note(doc, text):
    p = doc.add_paragraph()
    run = p.add_run("[PENDING] ")
    run.bold = True
    run.font.color.rgb = RGBColor(0x99, 0x00, 0x00)
    run2 = p.add_run(text)
    run2.italic = True
    return p


def table(doc, headers, rows, *, widths=None, caption=None, caption_above=True):
    if caption and caption_above:
        para(doc, caption, italic=True, size=10.5, space_after=3)
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        cell = t.rows[0].cells[i]
        cell.text = ""
        run = cell.paragraphs[0].add_run(h)
        run.bold = True
        run.font.size = Pt(10.5)
    for row in rows:
        cells = t.add_row().cells
        for i, value in enumerate(row):
            cells[i].text = ""
            run = cells[i].paragraphs[0].add_run(str(value))
            run.font.size = Pt(10.5)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    if caption and not caption_above:
        para(doc, caption, italic=True, size=10.5)
    doc.add_paragraph()
    return t


# ------------------------------------------------------------------ build
def build() -> Path:
    import yaml

    cfg = yaml.safe_load((REPO_ROOT / "config" / "experiment_config.yaml").read_text(
        encoding="utf-8"))
    policy = json.loads((REPO_ROOT / "policies" / "default_policy.json").read_text(
        encoding="utf-8"))
    refs = json.loads((REPO_ROOT / "docs" / "references.json").read_text(encoding="utf-8"))
    from cage_eval.cases import coverage, load_cases

    cases = []
    for split in ("design", "held_out"):
        d = REPO_ROOT / "cases" / split
        if d.is_dir():
            cases.extend(load_cases(d))
    cov = coverage(cases)
    gate = cfg["configuration_gate"]
    model = gate["agent_model"]
    bench = gate["benchmark"]

    doc = Document()
    style_document(doc)

    # ---------------------------------------------------------- title page
    para(doc, TITLE, align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=16)
    para(doc, SUBTITLE, align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=12.5)
    doc.add_paragraph()
    para(doc, ",  ".join(AUTHORS), align=WD_ALIGN_PARAGRAPH.CENTER, size=12.5)
    para(doc, AFFILIATION, align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11.5)
    doc.add_paragraph()
    para(doc, f"Corresponding author: {PENDING} (name and institutional e-mail not yet supplied)",
         align=WD_ALIGN_PARAGRAPH.CENTER, size=11, italic=True)
    doc.add_paragraph()
    para(doc, "Submitted to Elsevier, Computers & Security", align=WD_ALIGN_PARAGRAPH.CENTER,
         size=11.5)
    doc.add_paragraph()
    pending_note(doc,
                 "Draft status: the empirical Results section is not written. The configuration "
                 "gate is closed (scripts/check_gate.py exits non-zero on eight items), so no "
                 "benchmark run has been executed and no measured value appears anywhere in this "
                 "document. Every table that will carry results is present as a skeleton marked "
                 "PENDING, and the abstract carries a marked placeholder in place of a findings "
                 "sentence.")

    doc.add_page_break()

    # ------------------------------------------------------------- abstract
    doc.add_heading("Abstract", level=1)
    abstract = (
        "Tool-calling large language model agents act on content they retrieve, so an attacker "
        "who can write into a document, a message or a web page can steer consequential actions "
        "without touching the user's request. Per-call privilege control authorises each step in "
        "isolation and so admits chains whose steps are individually permissible, while "
        "provenance enforcement rejects any sensitive value whose only origin is untrusted "
        "content - including the legitimate value in a file the user named. That "
        "delegated-parameter case is inseparable by an origin check, so a binary guard must fail "
        "closed and lose the benign task. This paper presents CAGE (Composition-Aware Guard "
        "Evaluation for Agentic AI), a deterministic runtime reference monitor that intercepts "
        "every proposed tool call and returns allow, block or ask. Three rules are enforced: a "
        "source-to-sink rule over a per-run call history, an argument consistency rule that "
        "routes single-origin sensitive parameters from user-named sources to human confirmation "
        "rather than denying them, and a declared message-body heuristic for the in-band class "
        "origin rules cannot reach. An evaluation harness runs identical attack and benign cases "
        "under four conditions over a case set partitioned by attack template, classifies every "
        "trace into five adjudicated classes with baseline subtraction, and reports each rate as "
        "a numerator, a denominator and a percentage with Wilson intervals. Security is never "
        "reported without its paired usability cost. "
    )
    para(doc, abstract)
    pending_note(doc, "Findings sentence pending: one to two sentences stating the measured "
                      "held-out outcome, written from metrics_summary.csv once the gate opens. "
                      "The abstract is sized so that the findings sentence brings it within the "
                      "200-250 word range.")
    para(doc, f"Current word count of the abstract body: {len(abstract.split())} words "
              f"(target 200-250 including the pending findings sentence).",
         italic=True, size=10.5)

    doc.add_heading("Keywords", level=1)
    para(doc, "; ".join(KEYWORDS))

    # ----------------------------------------------------------- highlights
    doc.add_heading("Highlights", level=1)
    for h in HIGHLIGHTS:
        p = doc.add_paragraph(h, style="List Bullet")
        p.paragraph_format.space_after = Pt(3)
    para(doc, f"(Each highlight is {max(len(h) for h in HIGHLIGHTS)} characters or fewer, "
              f"within the 85-character limit.)", italic=True, size=10.5)

    # ---------------------------------------------------- graphical abstract
    doc.add_heading("Graphical abstract", level=1)
    if GRAPHICAL_ABSTRACT.is_file():
        doc.add_picture(str(GRAPHICAL_ABSTRACT), width=Inches(6.4))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    para(doc, "The CAGE runtime-defense workflow. A tool-calling agent reads untrusted content; "
              "every proposed call passes through the guard, where Rule A tracks sensitive reads "
              "to unauthorised sinks, Rule B checks sensitive arguments and routes delegated "
              "parameters to the user, and Rule C inspects outgoing message bodies. Each call "
              "ends in allow, block or ask, and the harness measures security together with "
              "usability.", italic=True, size=10.5)

    doc.add_page_break()

    # ------------------------------------------------------- 1 introduction
    doc.add_heading("1. Introduction", level=1)
    doc.add_heading("1.1 From text generation to consequential action", level=2)
    para(doc, "An agent that can send money, post messages and change account details is no "
              "longer only a text generator: its mistakes are transactions. The same agent reads "
              "documents, messages and web pages in order to do that work, and a model's context "
              "does not distinguish an instruction the user wrote from an instruction an attacker "
              "hid in retrieved content. Indirect prompt injection exploits exactly that "
              "confusion [1], [6], and benchmarks now exist to measure it in realistic tool-use "
              "environments [1], [3], [8], [16].")
    doc.add_heading("1.2 Why conventional mechanisms are insufficient", level=2)
    para(doc, "In-band defenses that inspect text are documented to fall to adaptive attacks "
              "[12], [13]. System-level enforcement is stronger: per-call privilege control "
              "constrains what each call may do [2], and provenance enforcement refuses a "
              "sensitive argument whose origin is untrusted [5]. Each leaves a gap. Per-call "
              "control authorises steps in isolation, so a chain whose steps are individually "
              "permissible passes. Provenance enforcement is binary, and when the only origin of "
              "a legitimate value is a document the user named - the payee that exists only "
              "inside the bill - it must fail closed and the benign task is lost.")
    doc.add_heading("1.3 The research gap", level=2)
    para(doc, "Composition-aware defense is not new [4], [14], [20], and this paper claims no "
              "priority for it. The narrow gap CAGE addresses is that the delegated-parameter "
              "class has been described as a residual failure mode [5] but not measured as a "
              "design choice: no study reports what happens when that class is routed to human "
              "confirmation instead of being denied - how often it occurs, how often "
              "confirmation recovers the task, and how often a user is asked to approve an "
              "attack. Independent reproduction is a second gap: ROPE has no third-party "
              "reproduction, while Progent already has one [9].")
    doc.add_heading("1.4 Contributions", level=2)
    for text in (
        "A deterministic runtime reference monitor with a three-way decision, whose "
        "guard-decision latency is measurable independently of model inference.",
        "An argument-consistency rule that routes single-origin sensitive parameters from "
        "user-named sources to human confirmation, with the interaction and security cost of "
        "that choice measured rather than asserted.",
        "A controlled evaluation harness, a documented case set partitioned by attack template, "
        "and a decision-inspection console, released as software.",
        "A measured account of the security, usability and interaction trade-off across four "
        "conditions, reporting non-supporting outcomes.",
    ):
        doc.add_paragraph(text, style="List Number")
    doc.add_heading("1.5 Research questions", level=2)
    table(doc, ["ID", "Question"], [
        ["RQ1", "How do per-call privilege control and origin enforcement compare on the "
                "selected tool-chaining and argument-manipulation cases?"],
        ["RQ2", "Does adding the CAGE rules to per-call privilege control change attack success?"],
        ["RQ3", "What are the trade-offs in clean utility, false denials, runtime and "
                "model-call/token overhead?"],
        ["RQ4", "How do the conditions behave on message-body attacks and on benign tasks whose "
                "correct value exists only in a user-named source?"],
    ], widths=[0.7, 5.3], caption="Table 1. Research questions.")
    para(doc, "Section 2 reviews related work, Section 3 states the threat model and the "
              "architecture, Section 4 the methodology, Section 5 the results, Section 6 the "
              "discussion and threats to validity, and Section 7 concludes.")

    # -------------------------------------------------------- 2 related work
    doc.add_heading("2. Related Work", level=1)
    doc.add_heading("2.1 Threat landscape and systematisation", level=2)
    para(doc, "Taxonomies of prompt-injection threats in agents [6] and design-pattern analyses "
              "[7] frame the problem; forensic work characterises how such attacks appear in "
              "logs [19].")
    doc.add_heading("2.2 Benchmarks and what they can discriminate", level=2)
    para(doc, "AgentDojo provides a dynamic tool-use environment with user and injection tasks "
              "[1]; ASB formalises attacks and defenses across agent components [16]; AgentLAB "
              "targets long-horizon attacks [3]; AgentDyn asks whether defenses remain deployable "
              "in dynamic environments [8]; AgentVigil automates black-box red-teaming [17]. A "
              "benchmark that saturates at zero attack success cannot discriminate between "
              "defenses, which is why this study reports utility and false denials alongside "
              "attack success.")
    doc.add_heading("2.3 In-band defenses and their adaptive-attack rebuttal", level=2)
    para(doc, "Detection and prompt-level defenses [13] and provable in-band defenses [15] are "
              "evaded by adaptive attacks [12]. Rule C in this work is therefore presented as "
              "coverage of an otherwise-uncovered class at a measured false-denial cost, not as a "
              "robust detector.")
    doc.add_heading("2.4 System-level enforcement: privilege control and provenance", level=2)
    para(doc, "Progent enforces per-call privilege policies [2]; ROPE routes origin policies and "
              "evaluates eleven defenses, documenting both the in-band class and the "
              "delegated-parameter class as residual failures [5]; design-by-construction "
              "approaches constrain the agent's control flow [11]; IPIGuard builds a tool "
              "dependency graph [14]; DISARM applies taint-gated counterfactual auditing [20]; "
              "ToolGuardian declares agent-tool security [4].")
    doc.add_heading("2.5 Human-in-the-loop and intent-conditioned authorisation", level=2)
    para(doc, "LLM-Sentry places a human in the loop for model-level risk [18] and "
              "intent-governed authorisation conditions tool use on declared intent [10]. CAGE "
              "differs in scope rather than in kind: confirmation is applied to one narrow, "
              "automatically identified class - a sensitive parameter whose single origin is a "
              "source the user named - and the cost of that confirmation is measured.")
    table(doc, ["Strand", "Representative work", "What it leaves open for this study"], [
        ["Per-call privilege control", "Progent [2]", "composition across calls; the delegated "
         "parameter is still allowed or denied, never deferred"],
        ["Origin / provenance enforcement", "ROPE [5]", "binary decision forces fail-closed on "
         "the delegated-parameter class; no third-party reproduction"],
        ["Dependency-graph and taint defenses", "IPIGuard [14], DISARM [20]",
         "in-band content with a correct address remains uncovered"],
        ["In-band detection", "[13], [15]", "documented adaptive-attack evasion [12]"],
        ["Human-in-the-loop authorisation", "LLM-Sentry [18], intent governance [10]",
         "no measured interaction cost for a narrowly targeted confirmation class"],
    ], widths=[1.5, 1.9, 2.9], caption="Table 2. Related-work strands and the openings this study "
                                      "addresses.")

    # ------------------------------------------- 3 threat model and design
    doc.add_heading("3. Threat Model and CAGE Architecture", level=1)
    doc.add_heading("3.1 Threat model", level=2)
    para(doc, "The attacker can write content the agent will read - a file body, a message, a "
              "web page, a tool result - but cannot modify the user's request, compromise the "
              "agent, the model weights or the tool implementations, or forge platform-level "
              "identity metadata, mirroring the model of [5]. Protected assets are the integrity "
              "of state-changing operations and the confidentiality of data the agent reads on "
              "the user's behalf. Three trust levels are used: trusted (the user's request and "
              "platform identity), declared-trusted (a record or source the request explicitly "
              "names), and untrusted (all other retrieved content).")
    para(doc, "Out of scope: white-box adaptive attacker optimisation, multimodal and GUI agents, "
              "malicious tool implementations [4], long-horizon memory poisoning [3], "
              "platform-side sender verification, semantic verification of user intent, and harm "
              "that never passes through a tool call. A low tool-call attack success rate "
              "therefore does not establish agent safety and is not reported as if it did.")
    doc.add_heading("3.2 Rules", level=2)
    para(doc, "Rule A (source to sink) records sensitive reads in a per-run call history and "
              "blocks a later state-changing call that carries that content to a destination the "
              "trusted request or a verified record does not authorise. Containment is tested by "
              "whole-value matching with explicit token-boundary handling, following [5], so that "
              "a value does not match inside a longer token.")
    para(doc, "Rule B (argument consistency and ask-routing) verifies sensitive recipients, "
              "destinations and amounts against the request or a trusted record. A value with an "
              "untrusted origin the request never named, or with no recorded origin at all, is "
              "blocked. A value whose single origin is a source the request named is routed to "
              "ask: the guard asserts nothing it cannot establish, and defers to the one party "
              "that can discriminate.")
    para(doc, "Rule C (message-body content check) inspects outgoing bodies for links, addresses, "
              "account identifiers and instruction-like text carried from untrusted tool output. "
              "It is a declared coverage heuristic with a measured false-denial cost: a "
              "paraphrased link or an attacker-authored sentence that never appeared verbatim in "
              "a tool result evades it by construction.")
    table(doc, ["Decision", "Meaning", "Counts as"], [
        ["allow", "the call is consistent with the trusted request or a verified source",
         "normal execution"],
        ["block", "positive evidence of an unauthorised flow or value",
         "prevention on an attacked case; false denial on a benign case"],
        ["ask", "unresolvable ambiguity: the guard cannot discriminate and the user can",
         "neither, until resolved; an approval on an attacked case is a "
         "confirmation-attributable attack success"],
    ], widths=[0.9, 3.0, 2.4], caption="Table 3. Decision semantics.")
    doc.add_heading("3.3 Reliability and architecture", level=2)
    para(doc, "An invalid policy or any exception raised during rule evaluation yields a block "
              "for every call whose risk class falls inside the configured fail-closed scope; the "
              "guard never degrades to an unguarded agent. The guard invokes no model, so its "
              "decision latency is in-process rule-evaluation time and is reported separately "
              "from end-to-end task latency, which for the compared conditions includes model "
              "calls. Every intercepted call produces one JSON record carrying the rule, the "
              "reason, machine-readable evidence and the decision latency; ask resolutions are "
              "separate records. The evaluation harness computes every metric from those records "
              "and the console only displays them.")
    if ARCHITECTURE.is_file():
        doc.add_picture(str(ARCHITECTURE), width=Inches(6.4))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        para(doc, "Figure 1. CAGE architecture. The enforcement path runs on the real control "
                  "path; the consumer path reads only what the enforcement path wrote.",
             italic=True, size=10.5)

    # ------------------------------------------------------ 4 methodology
    doc.add_heading("4. Experimental Methodology", level=1)
    doc.add_heading("4.1 Environment, model and benchmark", level=2)
    table(doc, ["Element", "Value in force", "Status"], [
        ["Language / testing", "Python 3.10+, pytest", "fixed"],
        ["Agent model", model["model_id"], "fixed"],
        ["Model revision", str(model["revision"]), "gate item"],
        ["Decoding", f"{model['decoding']}, temperature {model['temperature']}, "
                     f"seeds {model['seeds']}", "fixed"],
        ["Benchmark", f"{bench['name']} {', '.join(bench['suites'])}", "fixed"],
        ["Benchmark commit", str(bench["commit"]), "gate item"],
        ["Benchmark task IDs", str(bench["task_ids"]), "gate item"],
        ["Progent commit", str(gate["defenses"]["progent"]["commit"]), "gate item"],
        ["ROPE repository / commit", f"{gate['defenses']['rope']['repository']} / "
                                     f"{gate['defenses']['rope']['commit']}", "gate item"],
        ["C2 label in force", gate["defenses"]["rope"]["c2_label_in_force"], "conditional"],
        ["Policy / tool-risk table", f"{policy['version']}, "
                                     f"{len(policy['tools'])} declared tools", "fixed"],
        ["Experiment configuration", f"config {cfg['config_version']}", "fixed"],
    ], widths=[1.7, 3.3, 1.0], caption="Table 4. Experimental environment. Gate items are values "
                                      "the project will not invent; the runs do not start until "
                                      "they are supplied.")
    para(doc, "At temperature zero the three repeats measure environment and tool-ordering "
              "non-determinism only, not sampling variance; this is stated rather than left "
              "implicit. The AgentDojo environments are simulated, with synthetic accounts and no "
              "real credentials; the agent model and the guard are real code on the real control "
              "path. Because the benchmark simulates the platform metadata that origin "
              "enforcement assumes, results obtained here do not speak to whether that assumption "
              "holds in deployment.")
    doc.add_heading("4.2 Conditions", level=2)
    table(doc, ["Condition", "Description", "Status"], [
        ["C0", cfg["experiment"]["conditions"]["C0"], "runnable"],
        ["C1", cfg["experiment"]["conditions"]["C1"], "awaits Progent registration"],
        ["C2", cfg["experiment"]["conditions"]["C2"], "awaits ROPE registration"],
        ["C3", cfg["experiment"]["conditions"]["C3"], "awaits Progent registration"],
    ], widths=[0.9, 4.1, 1.3], caption="Table 5. Experimental conditions. A condition whose "
                                      "defense is not integrated is skipped with its reason "
                                      "recorded, never zero-filled, and never silently "
                                      "substituted; if the released ROPE implementation cannot be "
                                      "run, condition C2 is reported only as C2 (ROPE-inspired).")
    para(doc, "The planned contrasts are C1 against C0, C2 against C1, and C3 against C1. The "
              "last isolates the contribution of the CAGE rules, because the two conditions "
              "differ in exactly one component.")
    doc.add_heading("4.3 Case set and partition", level=2)
    para(doc, f"The case set contains {len(cases)} cases, partitioned by attack template into "
              f"{cov.get('split_design', 0)} design and {cov.get('split_held_out', 0)} held-out "
              f"cases. Coverage by target rule is: Rule A {cov.get('rule_A', 0)}, Rule B "
              f"{cov.get('rule_B', 0)}, Rule C {cov.get('rule_C', 0)}, and unlisted-tool "
              f"{cov.get('rule_A3', 0)}. Every case is constructed by the authors against the "
              f"environment and schema of a named benchmark task, and records that task's "
              f"identifier together with the repository and commit the identifier was read from; "
              f"no identifier was invented and no constructed case is reported as a benchmark "
              f"task. Reported performance comes from the held-out split; design-set figures are "
              f"shown separately and labelled as such.")
    para(doc, "The delegated-parameter pair is the centre of the set: a benign task whose payee "
              "exists only inside the file the user named, and an attacked twin with an injected "
              "payee in the same file. Both route to ask. The contrast case places the same "
              "injection in a file the request does not name, where the value is blocked "
              "outright. Benign counterparts are included for every attack family, and one "
              "control case places both recipient and amount in the request, where a correct "
              "guard must allow without asking.")
    doc.add_heading("4.4 Trace adjudication", level=2)
    adj = gate["adjudication"]
    para(doc, "Each trace is assigned exactly one of five classes: prevention, attack success, "
              "benign false denial, unrelated failure, invalid run. A sixth bookkeeping class, "
              "nominal, records a benign task that completed with no denial; it is counted and "
              "exported but enters no reported numerator, and is recorded as an approved "
              "deviation in the repository. Clean-task failures observed under C0 are subtracted "
              "before a trace is classified as a benign false denial, following the finding that "
              "most clean-task failures are agent incompetence rather than over-blocking [5]. A "
              "recorded success whose effect no executed call caused is re-scored.")
    para(doc, f"Primary coder: {adj['primary_coder']} (gate item). "
              f"{int(adj['double_coded_fraction'] * 100)}% of held-out traces are independently "
              f"double-coded and agreement is reported as {adj['agreement_statistic']}; "
              f"disagreements are resolved by {adj['disagreement_resolution']}.")
    doc.add_heading("4.5 Metrics and statistical reporting", level=2)
    para(doc, "Every rate is reported as numerator / denominator (percentage) with a 95% Wilson "
              "score interval, and a rate over an empty denominator is reported as undefined "
              "rather than zero. Security metrics are never reported without their paired "
              "usability metrics in the same table; the export refuses to write a table that "
              "breaks the pairing. Guard decision latency is reported separately from end-to-end "
              "runtime. Token counts are reported only where the wrapper exposes them and are "
              "otherwise recorded as not exposed, never estimated. With held-out sets of this "
              "size the study is exploratory: it is powered to detect large differences and to "
              "characterise behaviour per case, and no claim of statistical significance is made "
              "without a stated test.")
    table(doc, ["Metric", "Definition"], [
        ["Attack success rate", "attacked runs achieving the predefined attacker goal / all "
                                "valid attacked runs"],
        ["Clean task utility", "benign tasks completed with no attack present / all valid clean "
                               "runs"],
        ["Utility under attack", "attacked tasks still completed per the benchmark checker / all "
                                 "valid attacked runs"],
        ["False denial rate (call)", "benign calls denied / benign calls"],
        ["False denial rate (task)", "benign tasks classified as false denials / benign tasks"],
        ["False denial rate (delegated)", "as above, restricted to delegated-parameter tasks"],
        ["Guard decision latency", "mean and p95 wall-clock time from interception to decision, "
                                   "excluding all model time"],
        ["End-to-end overhead", "elapsed time per task relative to C0 under the same setup"],
        ["Model-call / token overhead", "model calls, and tokens where exposed"],
        ["Ask rate", "asks / sensitive calls"],
        ["Ask recovery rate", "benign tasks completed after approval / benign tasks that "
                              "triggered an ask"],
        ["Confirmation-attributable attack success",
         "attacked cases succeeding because a user approved an ask / valid attacked runs"],
    ], widths=[2.0, 4.3], caption="Table 6. Reported metrics.")
    doc.add_heading("4.6 Reproducibility", level=2)
    para(doc, "Seeds, model settings, commit hashes, the policy version and any per-case policy "
              "overlay are recorded in each run's metadata. One command reruns the unit tests, "
              "the guard behavioural probes and the pipeline self-test, then stops at the "
              "configuration gate; it proceeds to the main runs only when every gate item is "
              "supplied. The guard, harness, console, case set, policies, Docker configuration "
              "and raw logs are released together.")

    # ----------------------------------------------------------- 5 results
    doc.add_heading("5. Results", level=1)
    pending_note(doc,
                 "No benchmark run has been executed. The configuration gate is closed on eight "
                 "items (model revision, benchmark commit and task IDs, Progent commit, ROPE "
                 "repository and commit, primary trace coder, ethics approval status), and the "
                 "project does not invent them. The tables below are the skeletons that "
                 "metrics_summary.csv and per_case_results.json will fill; every cell reads "
                 "PENDING and no illustrative value has been inserted.")
    table(doc, ["Metric", "C0", "C1", "C2", "C3"], [
        [name, PENDING, PENDING, PENDING, PENDING] for name in
        ["Attack success rate", "Clean task utility", "Utility under attack",
         "False denial rate (call)", "False denial rate (task)",
         "False denial rate (delegated)", "Prevention rate"]
    ], widths=[2.1, 1.05, 1.05, 1.05, 1.05],
       caption="Table 7. Held-out security and usability, paired. Each cell will carry "
               "numerator / denominator (percentage) with its 95% Wilson interval.")
    table(doc, ["Ask-mode metric", "C3"], [[n, PENDING] for n in
          ["Ask rate", "Ask recovery rate", "Confirmation-attributable attack success",
           "Asks on delegated-parameter cases", "Asks on unlisted-tool cases"]],
          widths=[3.2, 1.6],
          caption="Table 8. Ask-mode behaviour, the mechanism this study measures.")
    table(doc, ["Cost", "C0", "C1", "C2", "C3"], [
        [n, PENDING, PENDING, PENDING, PENDING] for n in
        ["Guard decision latency, mean (ms)", "Guard decision latency, p95 (ms)",
         "End-to-end mean per task (s)", "Overhead relative to C0", "Model calls per task",
         "Tokens per task"]
    ], widths=[2.1, 1.05, 1.05, 1.05, 1.05],
       caption="Table 9. Enforcement cost. Guard decision latency excludes all model time and is "
               "not comparable across conditions that invoke a model; token counts are reported "
               "only where exposed.")
    table(doc, ["Trace class", "C0", "C1", "C2", "C3"], [
        [n, PENDING, PENDING, PENDING, PENDING] for n in
        ["Prevention", "Attack success", "Benign false denial", "Unrelated failure",
         "Invalid run", "Nominal (bookkeeping, not reported as one of the five)"]
    ], widths=[2.6, 0.9, 0.9, 0.9, 0.9],
       caption="Table 10. Trace classification per condition.")

    # -------------------------------------------------------- 6 discussion
    doc.add_heading("6. Discussion and Threats to Validity", level=1)
    doc.add_heading("6.1 Hypotheses", level=2)
    table(doc, ["ID", "Hypothesis", "Status"], [
        ["H1", "the conditions differ in attack success on at least some cases", PENDING],
        ["H2", "the added rules block cases that per-call control passes, at the price of false "
               "denials and overhead", PENDING],
        ["H3", "origin enforcement behaves differently from the lightweight rules because it "
               "checks structural origin", PENDING],
        ["H4", "a body-content rule catches injected links that address-level checks pass, at "
               "the price of some false denials", PENDING],
        ["H5", "origin enforcement denies benign delegated-parameter tasks that other conditions "
               "complete", PENDING],
    ], widths=[0.6, 4.3, 1.1], caption="Table 11. Hypotheses, to be evaluated against the "
                                      "held-out results. Non-supporting outcomes, including the "
                                      "possibility that the conditions do not differ, will be "
                                      "reported.")
    doc.add_heading("6.2 The confirmation trade-off", level=2)
    para(doc, "Routing the delegated-parameter class to confirmation converts an unresolvable "
              "ambiguity into a question. That has three measurable consequences, and the "
              "discussion will quantify each from the held-out results: benign tasks recovered "
              "that a fail-closed guard would have lost; interaction cost, as the share of "
              "sensitive calls that ask; and security cost, as attacks that succeed because a "
              "user approved. The third is the honest counterpart of the first - the same "
              "mechanism produces both - and reporting one without the other would misstate the "
              "contribution.")
    doc.add_heading("6.3 Threats to validity", level=2)
    for title, text in (
        ("Internal", "One model and configuration across conditions, identical cases and "
                     "scoring, a design/held-out split by attack template, fixed seeds, and "
                     "regression tests pinning each design case to an expected decision so that "
                     "a rule change cannot silently alter earlier behaviour."),
        ("External", "Limited, and stated as such: one benchmark family, two suites, one agent "
                     "model, and a purposively constructed case set. The results describe these "
                     "defenses on these cases. There is specific reason to expect that the "
                     "banking suite may not discriminate between the defended conditions on "
                     "attack success at all, which is why the design reports utility, false "
                     "denials and ask-mode behaviour as primary outcomes."),
        ("Construct", "Benchmark checkers measure task completion, a proxy for user-intent "
                      "satisfaction; effect-based re-scoring is adopted because checkers have "
                      "been documented to credit attacks that changed nothing [5]."),
        ("Conclusion", "With held-out sets of this size the study is exploratory. Wilson "
                       "intervals are reported and will be wide; no significance claim is made "
                       "without a stated test and sample size."),
    ):
        p = doc.add_paragraph()
        r = p.add_run(f"{title} validity. ")
        r.bold = True
        p.add_run(text)
    doc.add_heading("6.4 Limitations of the implementation", level=2)
    para(doc, "Rule A's recall depends on the sensitive values an adapter declares: without "
              "them, recorded content must appear verbatim in a later payload to match. Rule A is "
              "silent on sinks with no declared destination parameter. Amount verification "
              "accepts any numerically equal token in a trusted source, which under-blocks. Rule "
              "C matches pattern categories rather than paraphrase, and is expected to be the "
              "dominant false-denial driver. The call history assumes one run per instance and is "
              "not thread-safe, and decision latency grows with history length. These are "
              "reported rather than hidden, and each is testable from the released logs.")
    doc.add_heading("6.5 Ethical considerations", level=2)
    para(doc, f"All experiments run in simulated environments with synthetic accounts: no real "
              f"credentials, personal data, financial accounts or third-party systems are "
              f"involved. This is defensive security research; the injection techniques used are "
              f"already public in the cited benchmark literature, so the case set adds no "
              f"offensive capability beyond what those benchmarks distribute. Departmental ethics "
              f"approval status: {gate['ethics']['departmental_approval_status']} (gate item).")

    # -------------------------------------------------------- 7 conclusion
    doc.add_heading("7. Conclusion", level=1)
    para(doc, "CAGE is a deterministic runtime reference monitor for tool-calling agents with a "
              "three-way decision, an evaluation harness that reports security together with "
              "usability, and a decision-inspection console. Its empirical contribution is "
              "narrow by design: a measurement of whether routing single-origin sensitive "
              "parameters from user-named sources to human confirmation converts fail-closed "
              "utility loss into recoverable utility, and at what interaction and security cost. "
              "The engineering, the case set and the reproduction package are complete and "
              "released; the measurement itself awaits the pinned benchmark and defense "
              "revisions. No claim of complete agent safety is made: the evaluation concerns the "
              "tool-call attack surface, and harm that occurs only in the agent's natural-language "
              "reply is outside the evaluated scope.")
    pending_note(doc, "The concluding findings paragraph is written once the held-out results "
                      "exist.")

    # ------------------------------------------------------- back matter
    doc.add_heading("CRediT authorship contribution statement", level=1)
    pending_note(doc, "Role allocation per author not yet supplied. The statement will list, for "
                      "each of the four named authors, the CRediT roles actually performed "
                      "(conceptualisation, methodology, software, validation, formal analysis, "
                      "investigation, data curation, writing - original draft, writing - review "
                      "and editing, visualisation, supervision, project administration).")
    doc.add_heading("Declaration of competing interest", level=1)
    para(doc, "The authors declare that they have no known competing financial interests or "
              "personal relationships that could have appeared to influence the work reported in "
              "this paper.")
    doc.add_heading("Data availability", level=1)
    para(doc, "All data supporting this study are synthetic and are released with the software: "
              "the case set, the raw JSON decision logs, the exported metrics and the analysis "
              "configuration. No human-subject or personal data were collected.")
    pending_note(doc, "Archive reference pending: the Zenodo Version DOI for release v1.0.0 has "
                      "not been minted, so no DOI is cited here.")
    doc.add_heading("Code availability", level=1)
    para(doc, "The guard, the evaluation harness, the console, the case set, the policies, the "
              "Docker configuration and the reproduction scripts are released under Apache-2.0.")
    pending_note(doc, "Repository URL and Zenodo Version DOI pending; the repository metadata "
                      "currently carries a placeholder organisation name, and the archival "
                      "procedure is documented in the repository.")
    doc.add_heading("Declaration of generative AI use in scientific writing", level=1)
    para(doc, "During the preparation of this work the authors used an AI coding and writing "
              "assistant to implement and document the software, to draft and revise sections of "
              "this manuscript, and to prepare figures. All generated code was executed and "
              "tested, all reported software measurements were produced by running that code, and "
              "every reference was verified against the publication record. The authors reviewed "
              "and edited the content and take full responsibility for the content of the "
              "publication.")
    doc.add_heading("Ethics statement", level=1)
    para(doc, f"Experiments use simulated environments and synthetic accounts only; no real "
              f"credentials, personal data or third-party systems are involved. Departmental "
              f"ethics approval status: {gate['ethics']['departmental_approval_status']}.")

    doc.add_heading("References", level=1)
    for n in sorted(refs["entries"], key=int):
        entry = refs["entries"][n].replace("*", "")
        p = doc.add_paragraph(f"[{n}] {entry}")
        p.paragraph_format.space_after = Pt(4)
        for run in p.runs:
            run.font.size = Pt(10.5)
    p = doc.add_paragraph(
        "[21] F. A. Gul, M. Saleh, E. Razzaq, and A. Mustafa, \"CAGE: Composition-Aware Guard "
        "Evaluation for Agentic AI (v1.0.0) [Software],\" Zenodo, 2026. doi: PENDING")
    for run in p.runs:
        run.font.size = Pt(10.5)
    pending_note(doc, "Reference [21] is the project's own software citation; its Zenodo Version "
                      "DOI is minted when release v1.0.0 is archived.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT)
    return OUT


def main() -> int:
    over = [h for h in HIGHLIGHTS if len(h) > 85]
    if over:
        print("highlight exceeds 85 characters:", over, file=sys.stderr)
        return 1
    out = build()
    print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size:,} bytes)")
    print(f"highlights: {len(HIGHLIGHTS)}, longest {max(len(h) for h in HIGHLIGHTS)} characters")
    print("results section: PENDING (no benchmark run executed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
