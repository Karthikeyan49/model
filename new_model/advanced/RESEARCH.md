# RESEARCH — State of the art & roadmap for the OT/PLC vulnerability specialist

Scope: a **defensive** detector for IEC 61131-3 Structured Text (ST). This survey maps
current (2023–2026) research onto *this* system and proposes a prioritized roadmap.
Every concept is rated on the axes we care about — **PERFORMANCE** (throughput / cost),
**RELIABILITY** (calibrated, drift-aware, abstains when unsure), **ACCURACY**
(precision at fixed recall, soundness). Each entry gives: a one-line WHAT, why it helps
*here*, an implementation sketch sized to our mock-friendly stdlib style
(`dataclass` + small pure functions, no heavy deps), an honest difficulty/soundness note,
and citations. Citations are marked **(web)** if confirmed via search this session, or
**(prior knowledge — verify)** otherwise. Full URLs in the Sources section.

What we already ship (baseline for "Already have?" columns): hybrid analyzer+LLM triage,
conformal abstention (`conformal.py`), self-consistency (`selfconsistency.py`), dataflow
taint (`dataflow.py`, `interproc.py`), ensemble fusion (`ensemble.py`), reliability layer
(calibration ECE/Brier `calibration_metrics.py`, drift PSI/KS `drift.py`, active learning,
provenance, RAG triage, regression gate), and beyond-frontier modules (sound bounded
model-checking with witnesses for CWE-787/369/190 with flow-scoped guards `symbolic.py`,
verified repair `repair.py`, interprocedural per-CWE taint, variant hunting incl. CWE-125
`variant_hunt.py`, persistent knowledge graph with Beta-Bernoulli priors
`knowledge_graph.py`, Mondrian class-conditional conformal `mondrian_conformal.py`).

---

## 1. Executive summary

The system is unusually mature on the **reliability/uncertainty** axis (conformal +
Mondrian + calibration + drift) and on the **soundness** axis (a real bounded
model-checker that returns `unknown` instead of a false `safe`). The highest-leverage gains
now are: (a) **closing the calibration→risk loop** with conformal *risk* control and
Venn-Abers so the FP "budget" is a real, monotone, finite-sample guarantee on the metric
operators care about; (b) **making the conformal bound survive cross-customer drift** with
weighted/adaptive conformal (we already detect drift but cannot yet *correct* for it); and
(c) **raising precision on hard cases** with a relational (octagon) numeric domain that
kills the dominant false-positive source in our interval prover (correlated indices like
`a[i-j]`). The OT-specific moat is data and semantics, not model size: scan-time tasks
(timer/edge semantics, retain-memory, scan-cycle reachability, vendor intrinsics) are where
generic LLMs are weakest and where our graphs/provers structurally win.

Prioritized table (effort: S<½wk, M~1wk, L>2wk; impact on the named axis):

| # | Concept | Axis improved | Effort | Expected impact | Already have? |
|---|---|---|---|---|---|
| 1 | Conformal Risk Control (CRC) over FP-rate / miss-rate | RELIABILITY | S–M | High — turns our α "budget" into a *monotone* finite-sample risk bound | Partial (marginal FP only) |
| 2 | Venn-Abers calibration (IVAP) feeding conformal | RELIABILITY+ACCURACY | M | High — perfectly-calibrated probs → tighter, trustworthy thresholds | No (in progress) |
| 3 | Weighted/adaptive conformal under covariate shift | RELIABILITY | M | High — keeps the α guarantee across customer codebases (we detect drift but don't correct) | No |
| 4 | Relational octagon domain in `symbolic.py` | ACCURACY (soundness) | L | High — removes the #1 over-approx FP (`a[i-j]`, `i+j` correlated) | No (in progress) |
| 5 | Learn-then-Test (LTT) for multi-knob tuning | RELIABILITY | M | Med-High — jointly tune (α, ensemble weights, vote-N) with FWER control | No |
| 6 | Program slicing / PDG for evidence + LLM context | ACCURACY+PERF | M | Med-High — minimal slice ⇒ better LLM precision + cheaper prompts | No (in progress) |
| 7 | RCPS + calibration-beyond-ECE (adaptive/smooth ECE) | RELIABILITY | S | Med — honest calibration measurement; current ECE is bin-fragile | Partial (ECE/MCE/Brier) |
| 8 | k-induction / PDR upgrade to the prover | ACCURACY (soundness) | L | Med — prove `safe` for unbounded loops we currently mark `unknown` | No (bounded only) |
| 9 | Knowledge-level RAG exemplars (Vul-RAG style) | ACCURACY | M | Med — root-cause exemplars cut LLM FPs on triage | Partial (BM25 RAG) |
| 10 | Deep-ensemble disagreement as epistemic signal | RELIABILITY | S | Low-Med — disagreement → route to abstain/symbolic | Partial (ensemble fusion) |

Cross-cutting honesty: conformal/CRC guarantees are **marginal and assume exchangeability**
between calibration and test; the symbolic prover is sound only for its ST fragment;
multi-agent debate evidence is **mixed** (see §4). None of these are silver bullets.

---

## 2. Reliability & uncertainty

This is the system's differentiator — "abstain over guess" made into a measurable, bounded
property. The frontier here is moving from *coverage* guarantees to *risk* guarantees and
to validity *under shift*.

### 2.1 Conformal Risk Control (CRC)
**WHAT:** Generalizes conformal prediction from coverage to any *monotone* bounded loss:
pick the largest threshold λ whose expected loss on calibration stays ≤ α; the bound
E[L] ≤ α holds in finite samples under exchangeability (Angelopoulos et al., 2022). **(web)**
**Why here:** Our `conformal.py` controls a *false-positive fraction among emitted* by
sweeping observed confidences — that is morally split-conformal, but it is not framed as a
monotone risk and gives no formal control on *miss-rate* (the OT-critical risk: a missed
CWE-787 is worse than a FP). CRC lets us directly bound **miss-rate at fixed FP** or a
weighted cost, with a one-line monotone search instead of ad-hoc thresholding.
**Sketch (stdlib):** add `conformal_risk.py`:
```
def calibrate_risk(cal: list[tuple[float,bool]], alpha=0.1, loss="miss") -> Lambda:
    # loss(lambda) = mean over cal of bounded, monotone-in-lambda loss
    # CRC: pick smallest lambda s.t. (n/(n+1))*Lhat(lambda) + 1/(n+1) <= alpha
    lams = sorted({c for c,_ in cal})
    n = len(cal)
    for lam in lams:                       # monotone sweep, same shape as conformal.calibrate
        Lhat = _loss_at(cal, lam, loss)
        if (n/(n+1))*Lhat + 1/(n+1) <= alpha:
            return Lambda(lam, Lhat, n)
    return Lambda(max(lams), 1.0, n)       # conservative fallback
```
Reuses the exact `(confidence,is_true)` calibration tuples we already collect; emits a
`Lambda` dataclass parallel to `CalibratedThreshold`. **Difficulty/soundness:** Easy to
implement; the catch is the **monotonicity requirement** — losses must be non-increasing in
λ. FP-fraction is monotone; some composite costs are not (recent work shows non-monotone
CRC pitfalls — verify your loss). Still only *marginal*. Citations: Angelopoulos, Bates,
Candès, Jordan, Lei, *Conformal Risk Control* (web); non-monotonicity caveat arXiv 2604.01502 (web).

### 2.2 Learn-then-Test (LTT)
**WHAT:** Treats risk control as **multiple hypothesis testing**: each hyperparameter
configuration λ is a null "this λ violates the risk"; reject with a valid p-value and use
FWER-controlling procedures (Bonferroni/fixed-sequence) so *any* selected λ is risk-valid
(Angelopoulos et al., 2021). **(web)**
**Why here:** We have several knobs that interact — conformal α, ensemble weights
(`ensemble.py`), self-consistency N, mock-court trigger. Tuning them on the same data risks
silent overf_itting_ of the guarantee. LTT lets us search a **grid of configs** and still
ship a finite-sample risk bound on the chosen one.
**Sketch:** `ltt.py` taking `configs: list[Config]`, a per-config calibration loss, and a
risk α; compute a Hoeffding/empirical-Bernstein p-value per config and apply fixed-sequence
testing over a sensible order (e.g. increasing α). Return the risk-valid config set.
**Difficulty/soundness:** Medium. Honest note: power drops with many configs (multiplicity);
keep the grid small and ordered. Marginal guarantee. Citation: *Learn then Test* (web).

### 2.3 Venn-Abers predictors (IVAP)
**WHAT:** A calibrator (isotonic-regression-based) that is **automatically perfectly
calibrated** under exchangeability; outputs an interval [p0,p1] whose width *is* the
epistemic uncertainty (Vovk & Petej, 2014). **(web)**
**Why here:** Our conformal bound only "means" something if the input confidences are
calibrated — that is the explicit prerequisite noted in `calibration_metrics.py`. Today we
*measure* ECE but don't *fix* miscalibration. Dropping IVAP between the ensemble score and
the conformal threshold gives calibrated p and a free uncertainty width to gate abstention.
**Sketch:** `venn_abers.py` with pure-Python isotonic regression (pool-adjacent-violators):
```
def ivap(cal: list[tuple[float,bool]], s: float) -> tuple[float,float]:
    # fit g0 on cal+(s,0) and g1 on cal+(s,1) via PAVA; return (g0(s), g1(s))
    p0 = _pava_predict(cal + [(s, False)], s)
    p1 = _pava_predict(cal + [(s, True )], s)
    return p0, p1            # calibrated prob p = p1/(1-p0+p1); width = p1-p0 = uncertainty
```
PAVA is ~30 lines and dependency-free; matches our stdlib aesthetic. **Difficulty/soundness:**
Medium (PAVA + the IVAP merge formula). IVAP is the cheap inductive variant — the full VAP
retrains per test point. Calibration validity needs exchangeability (same caveat as
everything conformal). Citations: Vovk & Petej 2014 (web); NLU-with-Venn-ABERS arXiv 2205.10586 (web);
ref impl `ip200/venn-abers` (web).

### 2.4 Weighted / adaptive conformal under covariate shift
**WHAT:** Re-weight calibration scores by the likelihood ratio w(x)=dP_test/dP_cal so the
coverage/risk bound holds under **covariate shift** (Tibshirani, Foygel Barber, Candès,
Ramdas, 2019). Online variants (ACI) adapt the quantile when shift is unknown. **(web)**
**Why here:** This is the missing half of our drift story. `drift.py` *detects* PSI/KS drift
between PLC codebases and tells us to RECALIBRATE — but between recalibrations the marginal
bound is stale. Weighted conformal lets us *correct* for moderate shift using unlabeled
target code (estimate w from features we already extract), preserving the α guarantee across
customers without new labels.
**Sketch:** extend `conformal.calibrate` to accept `weights: list[float]`; when picking the
threshold, use the **weighted** empirical FP fraction Σ w·1[FP] / Σ w. Estimate w with a
tiny logistic "cal-vs-target" discriminator over existing features (LOC, op-mix, CWE
priors); fall back to w≡1 (current behavior) when the discriminator is uninformative.
**Difficulty/soundness:** Medium. Honest note: validity degrades if w is mis-estimated, and
it only handles *covariate* shift (P(y|x) stable) — label-shift across vendors needs
different machinery. Pair with `drift.py`: if KS/PSI is extreme, *abstain on recalibration*
rather than trust a large weight correction. Citations: Tibshirani et al. 2019, arXiv 1904.06019 (web).

### 2.5 Risk-Controlling Prediction Sets (RCPS)
**WHAT:** Construct sets whose risk is below α **with high probability** (1−δ), via an upper
confidence bound on the loss (Bates, Angelopoulos, Lei, Malik, Jordan, JACM 2021). **(web)**
**Why here:** CRC controls *expected* loss; RCPS gives the stronger PAC-style
"with prob ≥1−δ the deployed threshold's risk ≤ α." For a sellable security tool, a
**high-probability** miss-rate bound is a better contractual claim than an expectation.
**Sketch:** reuse §2.1's loss sweep but replace the point estimate with a Hoeffding/Bentkus
UCB: pick the smallest λ with `UCB_δ(Lhat(λ), n) ≤ α`. ~15 extra lines on top of CRC.
**Difficulty/soundness:** Small once CRC exists. Honest note: the UCB makes thresholds more
conservative (lower recall) than CRC for the same α — that is the price of the (1−δ)
guarantee; expose δ as a knob. Citations: Bates et al., *Distribution-free RCPS*, JACM 2021 (web).

### 2.6 Calibration beyond ECE (adaptive ECE, smooth ECE)
**WHAT:** Binned ECE is sensitive to bin count/edges; **AdaECE** uses equal-mass bins,
**SmoothECE** uses kernel smoothing with a principled bandwidth and is a consistent,
debiased calibration metric (Nixon et al. 2019; Błasiok & Nakkiran, ICLR 2024). **(web)**
**Why here:** `calibration_metrics.py` uses fixed-width bins — exactly the fragility these
papers flag, and our confidences are often sharp (many near 0/1), causing bin imbalance.
Adding AdaECE/SmoothECE makes our calibration claims robust and is a prerequisite for
trusting §2.1–2.3.
**Sketch:** add `ada_ece(pairs)` (sort by conf, equal-count bins) and `smooth_ece(pairs,
h)` (Gaussian-kernel reliability curve, RMS gap) next to the existing `evaluate`; keep the
same `CalibrationReport` shape. **Difficulty/soundness:** Small. Honest note: SmoothECE's
bandwidth selection matters; ship AdaECE first (trivial) and SmoothECE as a refinement.
Citations: Nixon et al. 2019 (web); SmoothECE, arXiv 2309.12236 / ICLR 2024 (web);
calibration survey arXiv 2308.01222 (web).

### 2.7 Selective prediction / deferral & deep ensembles
**WHAT:** Selective prediction adds a reject option with a risk–coverage curve; deep
ensembles (independent inits) give cheap, well-calibrated **epistemic** uncertainty
(Lakshminarayanan et al. 2017). **(web)**
**Why here:** We already abstain (conformal) and fuse an ensemble. The upgrade is to use
**ensemble disagreement** (variance across members / vote split from `selfconsistency.py`)
as an *independent* epistemic signal that routes a finding to the symbolic prover or to
human review — orthogonal to the conformal confidence. Report a risk–coverage curve as a
first-class metric (how much recall do we keep at FP≤α?).
**Sketch:** in `pipeline.py`, compute `disagreement = stdev(member_scores)`; if
`disagreement > τ` force `route="symbolic"` (or abstain). Add `risk_coverage()` to eval.
**Difficulty/soundness:** Small. Honest note: disagreement is a heuristic, not a guarantee;
use it to *route*, not to *certify*. Citations: Lakshminarayanan et al. 2017, arXiv 1612.01474 (web);
"Deep ensembles work, but are they necessary?" arXiv 2202.06985 (web — mixed evidence).

---

## 3. Accuracy & sound analysis

Our `symbolic.py` is a genuine bounded model-checker (sound for its fragment, emits
witnesses, returns `unknown` not false `safe`). The gains here come from **relational**
reasoning, **unbounded** proofs, **precise interprocedural** frameworks, and **slicing**.

### 3.1 Relational abstract domains (octagon, polyhedra)
**WHAT:** Domains that track relations between variables — octagon: ±x±y ≤ c
(Miné 2006), polyhedra: arbitrary linear inequalities (Cousot–Halbwachs 1978). **(web)**
**Why here:** This is the single biggest precision win available. Our prover's own caveat
says it sums correlated operands (`i+j` where `i=-j`) as full ranges, over-approximating to
`violated`. An octagon domain proves `safe` exactly for the `a[i-j]`, `a[i+c]`, bounds-coupled
cases that dominate ST array code → **fewer false positives without ever a false `safe`**.
**Sketch:** `octagon.py` backed by a Difference-Bound-Matrix (dict-of-dicts over the small
set of index vars in a block), with `assign`, `assume(guard)`, `join`, and a shortest-path
`close()` (Floyd–Warshall over ≤ 2n vars — fine for ST's tiny variable counts). Plug it in
as an alternative numeric backend behind `symbolic.py`'s interval engine; keep intervals as
the fast path and escalate to octagon on multi-variable indices.
**Difficulty/soundness:** **Large** — DBM closure + transfer functions + integer tightening
are subtle; bugs here threaten soundness, so gate behind the existing "never a false `safe`"
property tests and metamorphic checks. Cubic time / quadratic space in #vars, but #vars per
ST block is small. Citation: Miné, *The Octagon Abstract Domain*, arXiv cs/0703084 (web);
fast polyhedra (web).

### 3.2 k-induction & IC3/PDR
**WHAT:** **k-induction** proves invariants by strengthening base+step over k unrollings;
**IC3/PDR** (Bradley 2011) builds an inductive invariant incrementally without unrolling and
is proof/witness-producing. **(web)**
**Why here:** Our checker is *bounded* — it marks loops `unknown` past the bound. PDR/k-
induction would let us **prove `safe` for unbounded scan loops** (the common `FOR i:=0 TO
N` pattern), converting `unknown` into a real proof and shrinking the abstain bucket.
**Sketch:** start with **k-induction** (much simpler than IC3): encode the loop's transition
relation over our interval/octagon transfer functions and check base (≤k) + consecution
(state_k ∧ T ⇒ safe). A tiny fixpoint loop increasing k with a cap. Full IC3 is a later,
larger effort.
**Difficulty/soundness:** **Large.** k-induction can be *unsound without strengthening* if
the property isn't inductive — must add auxiliary invariants or fall back to `unknown`.
Keep the "never false `safe`" invariant as the hard gate. Citations: Bradley, IC3/PDR,
VMCAI 2011 (web); property-directed k-induction, Jovanović & Dutertre, FMCAD 2016 (web).

### 3.3 IFDS/IDE interprocedural frameworks
**WHAT:** Reps–Horwitz–Sagiv (POPL'95) reduce distributive interprocedural dataflow to
**graph reachability**, solvable precisely in polynomial time; IDE generalizes to
environment transformers (constant propagation, etc.). **(web)**
**Why here:** `interproc.py` uses function summaries + a call-graph fixpoint — good, but
ad-hoc. Re-expressing taint as an **IFDS exploded supergraph** gives *precise*,
context-sensitive source→sink paths (correct calling-context, no spurious cross-call flows)
and a principled basis for the per-CWE paths we already emit.
**Sketch:** `ifds.py`: build exploded nodes `(stmt, dataflow_fact)`; flow functions for
`gen/kill` of taint facts; tabulation algorithm (worklist over path edges + summary edges).
Facts = tainted ST variables; the realizable-path property gives our call-chain witness for
free. **Difficulty/soundness:** Medium-Large. Honest note: IFDS needs **distributive** flow
functions — fine for taint reachability, but sanitization-*sufficiency* (our known
limitation: we only check a guard *references* the param) is non-distributive and stays a
separate, conservative check. Citations: Reps, Horwitz, Sagiv, POPL'95 (web); Bodden,
IFDS/IDE in Soot (web).

### 3.4 Program slicing & PDG/SDG
**WHAT:** A **slice** is all statements that may affect a value at a point; the **SDG**
(Horwitz–Reps–Binkley 1990) makes *interprocedural* slices precise via context-sensitive
summary edges over a program/system dependence graph. **(web)**
**Why here:** Two wins. (1) **Evidence quality**: a backward slice from a sink is the
minimal proof of relevance — strictly better provenance than line lists in `provenance.py`.
(2) **LLM precision + cost**: feeding the LLM the *slice* instead of the whole POU removes
distractor code (a known FP source) and shrinks prompts (PERFORMANCE).
**Sketch:** `pdg.py`: build control- + data-dependence edges over the ST AST we already
parse; `backward_slice(node)` = graph reachability over reversed edges; interprocedural via
summary edges (or, cheaply, inline + intraprocedural slice first). Wire the slice into both
`rag_triage`/LLM context and the provenance record. **Difficulty/soundness:** Medium.
Honest note: precise SDG construction (especially for ST's `VAR_IN_OUT`, FB instances,
retain memory) is fiddly; start intraprocedural and grow. Citations: Weiser 1981 (prior
knowledge — verify); Horwitz, Reps, Binkley, *Interprocedural Slicing Using Dependence
Graphs*, TOPLAS 1990 (web).

### 3.5 Widening/narrowing, SMT-backed path conditions, value-set analysis
**WHAT:** Widening (∇) forces termination of fixpoints over infinite-height domains;
narrowing recovers precision; SMT solvers discharge path conditions exactly; VSA tracks the
set/strided-interval of values an address/var can hold. **(web/prior)**
**Why here:** Once we have octagon/polyhedra (§3.1) and loops (§3.2), **widening** is
*mandatory* for termination on unbounded loops; **narrowing** then claws back precision lost
to widening. **SMT-backed path conditions** would let `symbolic.py` reason about disjunctive
guards (`IF a OR b`) and modular INT arithmetic precisely instead of the current
conservative interval drop on `ELSE`/`ELSIF`. **VSA** generalizes our interval index
analysis to strided sets (e.g., `a[2*i]`), tightening both 787 and 125 checks.
**Sketch:** add `widen()`/`narrow()` to the octagon/interval lattices (standard threshold
widening using guard constants as thresholds — very effective for ST's literal bounds).
Optionally a thin `smt.py` shim with a **mock solver** interface (matching our mock-backend
philosophy) so the wiring exists before pulling in `z3`. **Difficulty/soundness:** Widening
small but precision-critical (a bad widening = useless `unknown`s, not unsoundness). SMT
integration medium; keep it optional so the stdlib build stays dependency-free. Citations:
Cousot & Cousot, abstract interpretation / widening (prior knowledge — verify); VSA
(Balakrishnan & Reps) (prior knowledge — verify).

---

## 4. LLM-for-vuln-detection SOTA (2023–2026)

Headline: **benchmarks moved the goalposts**. PrimeVul showed prior datasets were leaky and
over-easy — a 7B model scoring 68% F1 on BigVul dropped to ~3% F1 on PrimeVul, and SOTA LLMs
get <12% pair-accuracy distinguishing vulnerable vs. patched code (Ding et al., ICSE'25). This
is *the* reason our architecture forbids ungrounded LLM verdicts. **(web)**

### 4.1 Retrieval-augmented detection (knowledge-level RAG)
**WHAT:** Retrieve *root-cause/fix knowledge* (not just similar code) and condition the LLM
on it. **Vul-RAG** reports +16–24% accuracy and found 10 unknown Linux-kernel bugs (6 CVEs).
**(web)**
**Why here:** We have BM25 RAG over a CWE KB (`rag_triage.py`). The upgrade is **knowledge-
level** exemplars — functional-semantics + root-cause + fix triples mined from CISA
advisories/CVEfixes for ICS CWEs — which Vul-RAG shows beats code-similarity retrieval.
Directly raises triage precision (ACCURACY). **Sketch:** extend the KB schema with
`{root_cause, fix_pattern, functional_summary}` per entry; retrieve by ST functional
summary; inject as structured context. **Difficulty:** Medium (KB curation is the work).
Citation: Du et al., *Vul-RAG*, arXiv 2406.11147 / TOSEM (web).

### 4.2 Agentic / tool-use scanners
**WHAT:** LLM agents that *call tools* (run analyzers, fetch defs, navigate the repo) rather
than classify in one pass. 2025 work shows promise but high FP/variance with more autonomy.
**(web)** **Why here:** Our deterministic analyzer, dataflow, prover, and KG *are* exactly
the tools such an agent should call — we already have the tool layer, just not an agent
loop. A constrained agent that can request a slice (§3.4) or a symbolic check on demand
could improve hard-case recall. **Honest caveat:** studies report >33% degradation under
incomplete context and many spurious findings with more autonomy — keep the agent **on a
leash** (grounding-before-generation invariant, tool outputs as ground truth).
**Sketch:** a small `agent.py` orchestrator with a fixed tool set {analyze, slice, taint,
prove, kg_lookup} and a step cap; reuse `provenance.py` to log every tool call.
**Difficulty:** Medium-Large; defer until §1–§7 land. Citations: project-scale LLM-vuln
empirical study arXiv 2601.19239 (web); practical-repos agent benchmark arXiv 2503.03586 (web).

### 4.3 In-context learning vs. fine-tuning
**WHAT:** ICL with exemplars is cheap and adaptable; fine-tuning (incl. CWE-specialist LoRA)
can beat generalists on specific CWEs but risks overfitting leaky data. Specialist > generalist
for targeted CWEs (arXiv 2408.02329). **(web)** **Why here:** Validates our per-CWE LoRA MoE
plan (`moe_routing.yaml`) — but PrimeVul warns that fine-tuning gains can be dataset
artifacts. **Recommendation:** prefer **ICL + RAG exemplars** for breadth and reserve
LoRA fine-tuning for the few CWEs where we have clean, deduplicated ST data (787/125/190).
Citation: *Generalist to Specialist / CWE-specific detection*, arXiv 2408.02329 (web).

### 4.4 Multi-agent debate — mixed evidence
**WHAT:** Prosecutor/defense/judge or debate setups. **Evidence is genuinely mixed**: some
report gains (MAVUL, Mock-Court), while a controlled study finds plain **self-consistency
ties or beats** debate at equal compute. **(web)** **Why here:** This matches the caveat
already in our docs and in `mockcourt.py` (kept optional; the defense must consume *real*
dataflow evidence to be justified). **Recommendation:** keep debate as a narrow path for
hard cases only, and only when a non-LLM signal (taint/symbolic) grounds one side. Do **not**
make it the default. Citations: self-consistency-vs-debate arXiv 2511.07784, 2310.01798 (web,
already cited in our README); Mock-Court arXiv 2505.10961, MAVUL 2510.00317 (web).

### 4.5 LLM-as-judge calibration & hallucination/abstention
**WHAT:** LLM judges are themselves miscalibrated and biased; abstention/refusal calibration
is an active area. **Why here:** Our self-consistency confidences feed conformal — so the
*judge's* calibration is load-bearing. Run §2.6 calibration metrics **on the LLM-judge
scores specifically**, and prefer **abstention** when judge confidence is low rather than a
forced label. This is consistent with grounding-before-generation. **Difficulty:** Small
(measurement). Citation: NLP conformal survey arXiv 2405.01976 (web); calibration survey
2308.01222 (web).

### 4.6 Benchmarks to track
**WHAT/why:** Evaluate against **PrimeVul** (deduped, pair-metric, realistic) and **SVEN**
(808 manually-verified vuln/safe pairs; controlled-generation source) for the LLM layer;
**CVEfixes** for mining root-cause/fix exemplars; CWE-Bench/SecBench-style suites for breadth.
Avoid BigVul/Devign-only claims (leakage/label noise). For OT we must build our **own** ST
benchmark (see §5/§6) since these are C/C++-centric. Citations: PrimeVul / *How far are we?*
arXiv 2403.18624 + ICSE'25 (web); SVEN arXiv 2302.05319 (web); CVEfixes (prior knowledge —
verify); SECVULEVAL arXiv 2505.19828 (web).

---

## 5. OT/PLC/ICS specifics — the moat

Generic LLMs are trained mostly on C/Java/Python; **IEC 61131-3 ST and PLC execution
semantics are out-of-distribution**, and the real defenses (timing, scan-cycle, vendor
intrinsics) are *semantic*, not lexical. This is where graphs/provers beat a forward pass.

### 5.1 IEC 61131-3 semantics that change the analysis
- **Cyclic scan model:** code runs every scan; "reachability" must account for state that
  persists across cycles (RETAIN/PERSISTENT vars) — a flaw can be reachable only on the
  *N-th* scan. Generic LLMs have no scan-cycle prior.
- **Timers/edges (TON/TOF/TP, R_TRIG/F_TRIG):** standard function blocks with stateful,
  time-dependent semantics; off-by-one and race conditions hide here.
- **Fixed-width integers (SINT/INT/DINT, 8/16/32-bit) & implicit conversions:** the source
  of CWE-190 — our prover already models 16-bit INT wraparound (`symbolic.py`).
- **Arrays with non-zero/declared bounds `ARRAY[1..10]`** and pointer/reference types
  (`REF_TO`, `ADR`) → CWE-787/125; bounds are *declared*, which actually *helps* a sound
  analyzer (known constants for threshold widening, §3.5).
- **FB instances & `VAR_IN_OUT` aliasing:** interprocedural taint must respect instance
  state and in-out aliasing — fiddly for SDG/IFDS (§3.3–3.4), invisible to generic LLMs.
This semantic gap **is** the moat: our symbolic/interproc/variant layers encode it; a chat
model cannot reconstruct scan-cycle or 16-bit wrap semantics reliably.

### 5.2 Top ICS CWEs (prioritize detector coverage accordingly)
From CISA ICS advisories, the recurring weaknesses are **CWE-787 out-of-bounds write (~57
advisories), CWE-125 out-of-bounds read (~57), CWE-20 improper input validation (~73),
CWE-121 stack buffer overflow (~42), CWE-22 path traversal (~37)**, with CWE-190
integer overflow prominent in arithmetic-heavy logic. **(web)** Our prover/variant-hunt
already target 787/125/369/190 — the gap vs. the advisory distribution is **CWE-20 input
validation** and **CWE-22 path traversal** (both more about missing checks than numeric
bounds). **Recommendation:** add taint sinks/rules for input-validation and path handling
(maps cleanly onto IFDS taint, §3.3).

### 5.3 CISA advisories / CSAF as a live data source
**WHAT:** CISA publishes ICS advisories in machine-readable **CSAF** (VEX-capable JSON);
>450 advisories in 2025 across 200+ vendors. **(web)** **Why here:** A scheduled CSAF
ingest gives us (a) fresh **CWE frequency priors** for the Beta-Bernoulli weights in
`knowledge_graph.py`, (b) **root-cause/fix exemplars** for the Vul-RAG KB (§4.1), and (c)
**component→CVE** correlation data for `engine/correlate.py`. **Sketch:** `csaf_ingest.py`
that pulls the CSAF feed, extracts (vendor, product, CWE, CVE) tuples, and upserts KG nodes;
purely additive to existing schema. **Difficulty:** Small-Medium (parsing + scheduling).
Citation: CISA ICS advisories / CSAF (web).

### 5.4 PLC corpora & firmware/binary considerations
**WHAT:** **PLC-BEAD**: 700+ ST programs and 2,431 binaries across 4 compilers (CoDeSys,
OpenPLC v2/v3, GEB) — same ST source, divergent binaries; **PLCEmbed** companion; **OpenPLC**
as an IEC-61131-3 research controller. **(web)** **Why here:** PLC-BEAD is the best public
**ST source corpus** to (a) build our held-out ST benchmark (§6), (b) mine variant-hunt
seeds, and (c) study source→binary drift if we ever extend to firmware. **Firmware/binary**
is a different problem (stripped binaries, compiler-specific layouts) — out of current scope
but PLC-BEAD shows the same source yields very different binaries, so any future binary
detector must be cross-compiler robust. **Difficulty:** Corpus integration Small; binary
analysis Large/out-of-scope. Citations: PLC-BEAD, arXiv 2502.19725 / KDD'25 (web); 3-year
PLC run-time security study arXiv 2212.14296 (web); SoK ICS logic + formal verification
arXiv 2006.04806 (web).

### 5.5 What is genuinely hard for generic LLMs here
Scan-cycle reachability; cross-scan stateful timers; 8/16/32-bit modular arithmetic;
`VAR_IN_OUT` aliasing; vendor intrinsic FBs with undocumented side effects; **declared**
array bounds the model has never seen; and the requirement for a **replayable witness** an
operator can trust. Our beyond-frontier layer supplies exactly these (proofs, witnesses,
persistent KG). The moat is **OT-semantic soundness + curated ICS data**, not parameters.

---

## 6. Evaluation methodology

The PrimeVul lesson is that **how you evaluate dominates the headline number**. Discipline:

- **Precision at fixed recall (and recall at fixed FP):** report P@R=0.9 and R@FP=α, not raw
  F1 — F1 hides the FP/miss tradeoff operators actually buy. Plot the **risk–coverage curve**
  (ties directly to our abstention design and §2.7).
- **False-positive rate as a first-class metric** with confidence intervals (it is the moat).
  Report it *per CWE* (Mondrian groups) and marginally.
- **Calibration metrics:** ECE **plus** AdaECE/SmoothECE (§2.6) and Brier; show reliability
  diagrams. A detector with great F1 but bad ECE cannot support the conformal bound.
- **Pair-metric (vuln vs. patched):** adopt PrimeVul's pairwise evaluation for the LLM layer —
  it exposes shortcut-learning that per-sample accuracy hides. **(web)**
- **Statistical significance:** McNemar's test for paired classifier comparisons; bootstrap
  CIs for P/R/FP; for any *risk* claim, report the finite-sample CRC/RCPS bound, not just the
  point estimate. Apply multiplicity control (LTT, §2.2) when comparing many configs.
- **Held-out discipline & leakage pitfalls (the big one):**
  - **De-duplicate** by code/AST hash *before* splitting — PrimeVul found high duplication
    inflates scores; our `regression_gate.py` golden set must be dedup'd and disjoint from
    calibration. **(web)**
  - **Split by project/vendor**, not by function, so near-duplicate POUs don't straddle
    train/cal/test (especially with PLC vendor families).
  - **Temporal split** for CVE-derived data: calibrate on pre-date advisories, test on later
    ones, to mimic deployment and avoid future-leakage.
  - **Keep calibration ⫫ test ⫫ regression-gate**; the conformal bound is *only* valid if the
    calibration set is exchangeable with test and never trained/tuned on.
  - **Label noise:** ICS "fixed" commits may bundle unrelated changes (PrimeVul caveat);
    prefer human-verified or symbolic-witness-confirmed labels for the gold set.
- **Metamorphic robustness** (already in `metamorphic.py`): report verdict-stability under
  renaming/comment/constant-preserving mutations as a trust metric, not just accuracy.

---

## 7. Prioritized next-10 roadmap for THIS repo

Ordered by impact/effort. Each is sized to our stdlib/mock style and preserves the two
invariants (grounding-before-generation; abstain-over-guess).

1. **`conformal_risk.py` — CRC over miss-rate at fixed FP (and FP-rate).** *Why first:* small
   diff, reuses existing calibration tuples, and upgrades our central guarantee from an
   ad-hoc FP fraction to a monotone finite-sample *risk* bound — the OT-critical miss-rate.
   Effort S–M. (§2.1) Gate: verify loss monotonicity in property tests.
2. **`venn_abers.py` (IVAP) in front of conformal.** *Why:* makes input confidences
   *perfectly calibrated* (the stated prerequisite for the bound to mean anything) and yields
   a free uncertainty width for abstention. Effort M. (§2.3)
3. **Weighted conformal for covariate shift** (extend `conformal.calibrate(weights=...)` +
   tiny cal-vs-target discriminator). *Why:* closes the loop with `drift.py` — we currently
   *detect* drift but cannot *correct* it; this preserves α across customer codebases without
   new labels. Effort M. (§2.4)
4. **AdaECE + SmoothECE in `calibration_metrics.py`.** *Why:* our fixed-width ECE is fragile
   on sharp confidences; robust calibration measurement underpins items 1–3. Effort S. (§2.6)
5. **Octagon numeric backend for `symbolic.py`.** *Why:* removes the dominant false-positive
   source (correlated indices `a[i-j]`, `i+j`) while keeping "never a false `safe`". Biggest
   *accuracy* win, but **L** and soundness-sensitive — gate behind property + metamorphic
   tests. (§3.1, with widening §3.5)
6. **Program slicing (`pdg.py`) → provenance + LLM context.** *Why:* minimal backward slice =
   better evidence *and* cheaper, more precise LLM prompts (accuracy + performance). Effort M.
   (§3.4)
7. **`ltt.py` (Learn-then-Test) to jointly tune (α, ensemble weights, vote-N).** *Why:* we
   tune several interacting knobs; LTT keeps a valid risk bound on the chosen config. Effort
   M. (§2.2) Keep the config grid small.
8. **`csaf_ingest.py` — scheduled CISA CSAF feed → KG priors + Vul-RAG exemplars + correlate.**
   *Why:* turns the live ICS advisory stream into fresh CWE priors (Beta-Bernoulli weights),
   root-cause exemplars, and component-CVE correlation — compounding data moat. Effort S–M.
   (§5.3, §4.1)
9. **Knowledge-level RAG exemplars (Vul-RAG-style schema) in `rag_triage.py`.** *Why:* +16–24%
   reported accuracy from root-cause/fix retrieval vs. code-similarity; cuts LLM triage FPs.
   Effort M (KB curation is the cost). (§4.1)
10. **k-induction option in the prover (`symbolic.py`).** *Why:* converts `unknown` on bounded
    `FOR` loops into real `safe` proofs, shrinking the abstain bucket. **L** and must stay
    sound (strengthen or fall back to `unknown`). Defer behind octagon (item 5). (§3.2)

Deliberately *not* prioritized: full IC3/PDR (large, after k-induction), a fully autonomous
agent loop (mixed evidence, high FP risk — keep tools, leash the agent), and default
multi-agent debate (evidence says it ties/loses to self-consistency). Add CWE-20/CWE-22
taint sinks opportunistically alongside the IFDS work (§3.3) since they top the ICS
distribution.

---

## Sources

Reliability & uncertainty
- Angelopoulos, Bates, Candès, Jordan, Lei. *Conformal Risk Control.* (web) — https://people.eecs.berkeley.edu/~angelopoulos/publications/downloads/conformal-risk.pdf
- Non-monotonicity in Conformal Risk Control. arXiv 2604.01502. (web) — https://arxiv.org/pdf/2604.01502
- Angelopoulos, Bates, Candès, Jordan, Lei. *Learn then Test: Calibrating Predictive Algorithms to Achieve Risk Control.* (prior knowledge — verify) — arXiv 2110.01052
- Vovk, Petej. *Venn–Abers Predictors.* UAI 2014. (web) — https://www.auai.org/uai2014/proceedings/individuals/166.pdf ; arXiv 1211.0025 — https://arxiv.org/pdf/1211.0025
- *Calibration of NLU Models with Venn–ABERS Predictors.* arXiv 2205.10586. (web) — https://arxiv.org/pdf/2205.10586
- venn-abers reference implementation. (web) — https://github.com/ip200/venn-abers
- Tibshirani, Foygel Barber, Candès, Ramdas. *Conformal Prediction Under Covariate Shift.* NeurIPS 2019, arXiv 1904.06019. (web) — https://arxiv.org/abs/1904.06019
- Bates, Angelopoulos, Lei, Malik, Jordan. *Distribution-free, Risk-controlling Prediction Sets.* JACM 2021. (web) — https://people.eecs.berkeley.edu/~angelopoulos/ (RCPS)
- Nixon, Dusenberry, Zhang, Jerfel, Tran. *Measuring Calibration in Deep Learning* (Adaptive Calibration Error). CVPRW 2019. (web, secondary) — see arXiv 2308.01222 survey below
- Błasiok, Nakkiran. *Smooth ECE: Principled Reliability Diagrams via Kernel Smoothing.* ICLR 2024, arXiv 2309.12236. (web) — https://arxiv.org/html/2309.12236
- *Calibration in Deep Learning: A Survey of the State-of-the-Art.* arXiv 2308.01222. (web) — https://arxiv.org/pdf/2308.01222
- Lakshminarayanan, Pritzel, Blundell. *Simple and Scalable Predictive Uncertainty Estimation using Deep Ensembles.* NeurIPS 2017, arXiv 1612.01474. (web) — https://arxiv.org/abs/1612.01474
- *Deep Ensembles Work, But Are They Necessary?* arXiv 2202.06985. (web, mixed evidence) — https://arxiv.org/pdf/2202.06985
- Mondrian Confidence Machine — Vovk, Lindsay, Nouretdinov, Gammerman, 2003. (prior knowledge — verify) — referenced in `mondrian_conformal.py`

Accuracy & sound analysis
- Miné. *The Octagon Abstract Domain.* HOSC 2006, arXiv cs/0703084. (web) — https://arxiv.org/pdf/cs/0703084
- Cousot, Halbwachs. *Automatic Discovery of Linear Restraints Among Variables of a Program* (polyhedra). POPL 1978. (prior knowledge — verify)
- Singh, Püschel, Vechev. *Fast Polyhedra Abstract Domain.* POPL 2017. (web) — https://dl.acm.org/doi/10.1145/3093333.3009885
- Bradley. *SAT-Based Model Checking without Unrolling (IC3/PDR).* VMCAI 2011. (web) — see https://people.eecs.berkeley.edu/~alanmi/publications/2011/fmcad11_pdr.pdf (efficient PDR impl)
- Jovanović, Dutertre. *Property-Directed k-Induction.* FMCAD 2016. (web/prior — verify)
- Reps, Horwitz, Sagiv. *Precise Interprocedural Dataflow Analysis via Graph Reachability (IFDS).* POPL 1995. (web) — https://pages.cs.wisc.edu/~fischer/cs701.f14/popl95.pdf
- Bodden. *Inter-procedural Data-flow Analysis with IFDS/IDE and Soot.* SOAP 2012. (web) — http://www.bodden.de/pubs/bodden12inter-procedural.pdf
- Horwitz, Reps, Binkley. *Interprocedural Slicing Using Dependence Graphs.* TOPLAS 1990. (web) — https://www.csa.iisc.ac.in/~raghavan/CleanedPav2011/horwitz-sdg-slicing-1990.pdf
- Weiser. *Program Slicing.* ICSE 1981 / IEEE TSE 1984. (prior knowledge — verify)
- Cousot, Cousot. *Abstract Interpretation* (widening/narrowing). POPL 1977. (prior knowledge — verify)
- Balakrishnan, Reps. *Analyzing Memory Accesses in x86 Executables* (Value-Set Analysis). CC 2004. (prior knowledge — verify)

LLM-for-vuln-detection
- Ding et al. *Vulnerability Detection with Code Language Models: How Far Are We?* (PrimeVul). ICSE 2025, arXiv 2403.18624. (web) — https://www.emergentmind.com/papers/2403.18624 ; https://dl.acm.org/doi/10.1109/ICSE55347.2025.00038
- Du, Zheng et al. *Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG.* arXiv 2406.11147 / TOSEM. (web) — https://arxiv.org/abs/2406.11147
- He, Vechev. *Large Language Models for Code: Security Hardening and Adversarial Testing (SVEN).* CCS 2023, arXiv 2302.05319. (web) — https://arxiv.org/abs/2302.05319
- *SECVULEVAL: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection.* arXiv 2505.19828. (web) — https://arxiv.org/pdf/2505.19828
- *From Generalist to Specialist: Exploring CWE-Specific Vulnerability Detection.* arXiv 2408.02329. (web) — https://arxiv.org/pdf/2408.02329
- *LLM-based Vulnerability Detection at Project Scale: An Empirical Study.* arXiv 2601.19239. (web) — https://arxiv.org/pdf/2601.19239
- *Benchmarking LLMs and LLM-based Agents in Practical Vulnerability Detection for Code Repositories.* arXiv 2503.03586. (web) — https://arxiv.org/pdf/2503.03586
- *Conformal Prediction for NLP: A Survey.* arXiv 2405.01976. (web) — https://arxiv.org/pdf/2405.01976
- Self-consistency vs. multi-agent debate. arXiv 2511.07784; 2310.01798. (web, already in README) — https://arxiv.org/pdf/2511.07784 ; https://arxiv.org/pdf/2310.01798
- Mock-Court agents. arXiv 2505.10961; MAVUL arXiv 2510.00317. (web, already in README) — https://arxiv.org/pdf/2505.10961 ; https://arxiv.org/pdf/2510.00317
- Conformal Abstention Framework. arXiv 2405.01563. (web, already in code) — https://arxiv.org/pdf/2405.01563
- CVEfixes dataset (Bhandari, Naseer, Moonen). MSR/PROMISE 2021. (prior knowledge — verify)

OT/PLC/ICS
- *Bridging the PLC Binary Analysis Gap: A Cross-Compiler Dataset (PLC-BEAD / PLCEmbed) and Neural Framework for ICS.* arXiv 2502.19725 / KDD 2025. (web) — https://arxiv.org/abs/2502.19725
- *Towards Comprehensively Understanding the Run-time Security of PLCs: A 3-year Empirical Study.* arXiv 2212.14296. (web) — https://arxiv.org/pdf/2212.14296
- *SoK: Attacks on Industrial Control Logic and Formal Verification-Based Defenses.* arXiv 2006.04806. (web) — https://arxiv.org/pdf/2006.04806
- OpenPLC: An IEC 61131-3 Compliant Open Source Controller for Cybersecurity Research. (web) — https://www.researchgate.net/publication/326542218
- CISA ICS Advisories (CSAF/VEX feed) + 2025 recap (CWE frequencies: 787≈57, 125≈57, 20≈73, 121≈42, 22≈37; >450 advisories in 2025). (web) — https://www.cisa.gov/news-events/ics-advisories ; https://socradar.io/blog/cisa-industrial-control-systems-ics-advisories-2025/
- MITRE CWE — CWE-787/125/369/190/20/22 definitions. (prior knowledge — verify) — https://cwe.mitre.org/
- IEC 61131-3 standard (ST language & FB semantics). (prior knowledge — verify)
