"""Conformal Risk Control (CRC) + Learn-then-Test (LTT) — bounding the MISS rate.

The sibling module ``conformal.py`` bounds the false-POSITIVE fraction *among the
findings we emit*. That is only one side of a security tool's safety tradeoff. The
other, often costlier side is the false-NEGATIVE (miss) rate: of the
vulnerabilities that are genuinely present, what fraction did we abstain on / hide
from the operator? A scanner that emits nothing has a perfect false-positive rate
and is useless. This module supplies the missing guarantee: a distribution-free,
finite-sample upper bound on the EXPECTED miss rate (recall risk).

Two complementary, rigorously-cited procedures are implemented:

CRC — Conformal Risk Control
    Angelopoulos, Bates, Fisch, Lei & Schuster, "Conformal Risk Control",
    arXiv:2208.02814 (2022/2025). CRC generalises split conformal prediction from
    coverage to the EXPECTATION of *any* loss that is monotone in a one-dimensional
    threshold and bounded above by ``B``. With ``n`` exchangeable calibration
    points it selects a threshold whose loss on a fresh test point satisfies the
    finite-sample guarantee  E[L_{n+1}] <= alpha  (Theorem 1 of the paper). The
    selection rule (their Eq. for lambda-hat; ``core/get_lhat.py`` in the authors'
    reference code) is

        lambda_hat = inf { lambda : (n/(n+1)) * R_hat_n(lambda) + B/(n+1) <= alpha }
        with R_hat_n(lambda) = (1/n) * sum_i L_i(lambda).

    The (B/(n+1)) inflation is what upgrades the *empirical* mean to a *finite-sample*
    bound on the expectation; it is tight up to O(1/n).

LTT — Learn then Test
    Angelopoulos, Bates, Candes, Jordan & Lei, "Learn then Test: Calibrating
    Predictive Algorithms to Achieve Risk Control", arXiv:2110.01052 (2021). LTT
    reframes "is the risk at this threshold <= alpha?" as a multiple-hypothesis
    test: each candidate threshold lambda is a null H_lambda: R(lambda) > alpha. A
    valid p-value is computed per candidate from a concentration inequality for a
    bounded mean, a family-wise-error-rate (FWER) correction is applied, and every
    threshold whose corrected p-value falls at or below delta is *certified*:
    P(any certified lambda has true risk > alpha) <= delta. This gives a high-
    probability (1 - delta) guarantee, in contrast to CRC's in-expectation one.

Soundness / honesty notes
-------------------------
* Both guarantees require exchangeability (the usual iid-style assumption) between
  the calibration data and the data seen in production. If the production
  distribution drifts, the guarantee degrades silently — pair this with the drift
  monitor before trusting the number.
* The CRC monotonicity requirement is real and is enforced/documented per loss:
  the loss must be monotone in the search parameter, otherwise lambda_hat is not
  guaranteed to control the risk. For the FNR loss we make the monotone direction
  explicit below.
* Everywhere we are forced to choose, we return the MORE conservative value
  (e.g. emit-everything when nothing meets the FNR budget; the *largest* certified
  threshold's risk, the largest p-value across a tie) and flag it, rather than
  over-promise a guarantee we cannot back.
* Pure stdlib, deterministic, zero backends — usable directly in tests.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

# A calibration pair is (confidence, is_true_vulnerability), matching conformal.py.
CalPair = Tuple[float, bool]

# A loss callable maps (lambda, calibration) -> empirical risk R_hat(lambda) in
# [0, B]. It MUST be monotone NON-INCREASING in lambda for the CRC guarantee to
# hold (see ``control_risk`` docstring for the sign convention).
LossFn = Callable[[float, Sequence[CalPair]], float]


# --------------------------------------------------------------------------- #
# Built-in losses
# --------------------------------------------------------------------------- #
def fnr_loss(lam: float, calibration: Sequence[CalPair]) -> float:
    """Miss rate (false-negative rate) among TRUE vulnerabilities at emit-threshold
    ``lam``: a finding is emitted iff ``confidence >= lam``, so a true vuln is
    *missed* (abstained) iff its confidence is strictly below ``lam``.

        FNR(lam) = #{true vulns with confidence < lam} / #{true vulns}

    Monotonicity: FNR is NON-DECREASING in ``lam`` (raising the bar abstains on
    more true findings) and therefore NON-INCREASING in the CRC search parameter
    ``t = -lam`` that :func:`control_risk` actually iterates over. Bounded in
    [0, 1], so ``B = 1`` is the correct loss bound. If there are no true vulns the
    miss rate is undefined; we conservatively report 0.0 (nothing can be missed).
    """
    trues = [c for c, t in calibration if t]
    if not trues:
        return 0.0
    missed = sum(1 for c in trues if c < lam)
    return missed / len(trues)


# --------------------------------------------------------------------------- #
# Conformal Risk Control
# --------------------------------------------------------------------------- #
@dataclass
class RiskControlResult:
    """Outcome of :func:`control_risk`.

    Attributes
    ----------
    threshold:
        The selected emit-threshold lambda_hat. Emit a finding iff
        ``confidence >= threshold``.
    achieved_risk:
        The *raw* empirical risk R_hat(threshold) on the calibration set at the
        chosen threshold (NOT the inflated bound). For an achievable budget this
        is <= alpha.
    bound:
        The finite-sample CRC bound at the chosen threshold,
        ``(n/(n+1)) * R_hat + B/(n+1)``. This is the quantity guaranteed to be
        <= alpha when ``feasible`` is True; it is what actually certifies the
        expectation control.
    alpha:
        Target risk level (the expectation E[L] is controlled at this level).
    n:
        Number of calibration points used.
    B:
        Assumed upper bound on the loss.
    loss:
        Name of the loss controlled ("fnr" or "custom").
    feasible:
        True iff some threshold met the CRC budget. When False, ``threshold`` is
        the most conservative fallback (emit-everything for FNR) and NO guarantee
        at level ``alpha`` is claimed — see :func:`report`.
    """
    threshold: float
    achieved_risk: float
    bound: float
    alpha: float
    n: int
    B: float
    loss: str
    feasible: bool


def _candidate_thresholds(calibration: Sequence[CalPair]) -> List[float]:
    """Split-conformal-style candidate grid: the observed confidences plus a point
    strictly below the minimum so that 'emit everything' is reachable. Sorted
    descending so we scan from the riskiest (largest lambda) toward the safest,
    and can stop at the LARGEST lambda that still satisfies the budget.
    """
    confs = sorted({c for c, _ in calibration}, reverse=True)
    if not confs:
        return [0.0]
    # A threshold strictly <= the smallest confidence emits every finding and so
    # drives the FNR loss to its minimum (0 if recall can be perfect). Use a value
    # below the minimum observed confidence; clamp at 0.0 since confidences are >=0.
    emit_all = min(confs[-1], 0.0)
    if emit_all < confs[-1]:
        confs.append(emit_all)
    elif confs[-1] > 0.0:
        confs.append(0.0)
    return confs


def control_risk(
    calibration: Sequence[CalPair],
    alpha: float = 0.1,
    loss: str | LossFn = "fnr",
    B: float = 1.0,
) -> RiskControlResult:
    """Select an emit-threshold that controls E[loss] <= ``alpha`` via Conformal
    Risk Control (Angelopoulos et al., arXiv:2208.02814).

    Parameters
    ----------
    calibration:
        List of ``(confidence, is_true_vulnerability)`` pairs, exchangeable with
        production data.
    alpha:
        Target on the *expected* loss of a fresh test point.
    loss:
        ``"fnr"`` for the built-in miss-rate loss, or any callable
        ``LossFn(lambda, calibration) -> R_hat`` that is **monotone non-increasing
        in lambda** and bounded in ``[0, B]``. The monotonicity is a precondition
        of the CRC theorem; if it is violated the returned threshold does not carry
        the guarantee.
    B:
        Upper bound on the loss (1.0 for any rate/fraction loss).

    Returns
    -------
    RiskControlResult

    Method
    ------
    We iterate candidate thresholds from largest to smallest and pick the LARGEST
    emit-threshold lambda whose finite-sample-corrected risk satisfies

        (n / (n + 1)) * R_hat(lambda) + B / (n + 1) <= alpha,

    i.e. CRC's  lambda_hat = inf{ lambda : ... <= alpha }  expressed over the
    monotone search parameter ``t = -lambda`` (decreasing lambda == decreasing FNR
    == decreasing loss, matching the paper's "loss non-increasing in the
    parameter" convention). Picking the largest feasible lambda emits as *few*
    findings as the budget allows, i.e. it controls the miss rate while keeping the
    false-positive surface minimal.

    Guarantee & caveats
    -------------------
    Under exchangeability and the monotonicity precondition, E[L_{n+1}(lambda_hat)]
    <= alpha with finite-sample (non-asymptotic) validity, distribution-free
    (Theorem 1, arXiv:2208.02814). The bound is in EXPECTATION, not high-
    probability (use :func:`learn_then_test` for the latter). If no candidate meets
    the budget we return the most conservative threshold (emit-everything for FNR,
    minimising the miss rate) with ``feasible=False`` and make NO alpha-level
    claim.
    """
    loss_fn: LossFn
    loss_name: str
    if callable(loss):
        loss_fn, loss_name = loss, "custom"
    elif loss == "fnr":
        loss_fn, loss_name = fnr_loss, "fnr"
    else:
        raise ValueError(f"unknown loss {loss!r}; pass 'fnr' or a callable")

    n = len(calibration)
    if n == 0:
        # No data => no guarantee possible. Emit everything (most conservative for
        # a miss-rate budget) and flag infeasible.
        return RiskControlResult(0.0, 0.0, B, alpha, 0, B, loss_name, feasible=False)

    candidates = _candidate_thresholds(calibration)

    # Scan from largest (riskiest) lambda down; keep the largest lambda whose CRC
    # bound clears alpha. Because the loss is monotone, once a lambda clears the
    # budget every smaller lambda also clears it, so the first clearing lambda in
    # this descending scan is the largest feasible one == lambda_hat.
    for lam in candidates:
        r_hat = loss_fn(lam, calibration)
        bound = (n / (n + 1)) * r_hat + B / (n + 1)
        if bound <= alpha + 1e-12:
            return RiskControlResult(
                threshold=lam,
                achieved_risk=round(r_hat, 6),
                bound=round(bound, 6),
                alpha=alpha,
                n=n,
                B=B,
                loss=loss_name,
                feasible=True,
            )

    # Nothing met the budget: fall back to the most conservative threshold. For a
    # miss-rate loss that is the smallest threshold (emit everything => fewest
    # misses). Report its (non-guaranteeing) risk honestly.
    lam = candidates[-1]
    r_hat = loss_fn(lam, calibration)
    bound = (n / (n + 1)) * r_hat + B / (n + 1)
    return RiskControlResult(
        threshold=lam,
        achieved_risk=round(r_hat, 6),
        bound=round(bound, 6),
        alpha=alpha,
        n=n,
        B=B,
        loss=loss_name,
        feasible=False,
    )


# --------------------------------------------------------------------------- #
# Learn then Test
# --------------------------------------------------------------------------- #
def _binom_cdf(k: int, n: int, p: float) -> float:
    """Exact P(Binomial(n, p) <= k) via summation (stdlib ``math.comb``).

    Conservative at the boundaries: p<=0 => mass at 0; p>=1 => mass at n.
    """
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0  # all mass at 0 <= k
    if p >= 1.0:
        return 0.0  # all mass at n > k
    total = 0.0
    for i in range(0, k + 1):
        total += math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
    # Clamp tiny FP drift into [0, 1].
    return min(1.0, max(0.0, total))


def _kl_bernoulli(a: float, b: float) -> float:
    """Binary relative entropy h_1(a, b) = a log(a/b) + (1-a) log((1-a)/(1-b)),
    the rate function in the Chernoff/Hoeffding tail bound for a bounded mean.
    Handles the 0 log 0 = 0 boundary cases.
    """
    if b <= 0.0 or b >= 1.0:
        # Degenerate target; the Hoeffding term is not informative here.
        return 0.0
    term1 = 0.0 if a <= 0.0 else a * math.log(a / b)
    term2 = 0.0 if a >= 1.0 else (1.0 - a) * math.log((1.0 - a) / (1.0 - b))
    return term1 + term2


def hoeffding_p_value(r_hat: float, alpha: float, n: int) -> float:
    """Simple one-sided Hoeffding p-value for H: R(lambda) > alpha, loss in [0, 1].

    From Hoeffding's inequality P(R_hat - R <= -t) <= exp(-2 n t^2): under the null
    R >= alpha, observing an empirical mean as low as R_hat <= alpha has

        p = exp(-2 n (alpha - R_hat)^2)   (and p = 1 when R_hat >= alpha).

    This is the additive, distribution-free bound used as the simplest valid LTT
    p-value. It is looser than :func:`hoeffding_bentkus_p_value`; we expose both
    and default LTT to HB.
    """
    if n <= 0:
        return 1.0
    gap = alpha - r_hat
    if gap <= 0.0:
        return 1.0
    return min(1.0, math.exp(-2.0 * n * gap * gap))


def hoeffding_bentkus_p_value(r_hat: float, alpha: float, n: int) -> float:
    """Hoeffding-Bentkus (HB) p-value for H: R(lambda) > alpha, loss in [0, 1]
    (Learn then Test, arXiv:2110.01052; Bates et al. arXiv:2101.02703).

        p_HB = min( exp{ -n * h_1(min(R_hat, alpha), alpha) },
                    e * P(Binomial(n, alpha) <= ceil(n * R_hat)) )

    where h_1(a, b) = a log(a/b) + (1-a) log((1-a)/(1-b)). The first (Hoeffding /
    relative-entropy) term is valid only on R_hat <= alpha, hence ``min(R_hat,
    alpha)``; for R_hat >= alpha that term is 1 and the test correctly fails to
    reject. The second (Bentkus) term, e * P(Bin(n, alpha) <= ceil(n R_hat)), is a
    valid p-value for a bounded mean and is tighter in the small-sample / small-
    alpha regime. Taking the min of two valid p-values is itself valid and strictly
    more powerful than either alone. We return the conservative (larger) value
    whenever numerics are ambiguous.
    """
    if n <= 0:
        return 1.0
    r_hat = min(max(r_hat, 0.0), 1.0)
    # Hoeffding / Chernoff term (valid for R_hat <= alpha).
    if r_hat >= alpha:
        hoeff = 1.0
    else:
        hoeff = math.exp(-n * _kl_bernoulli(r_hat, alpha))
    # Bentkus term.
    k = math.ceil(n * r_hat)
    bentkus = math.e * _binom_cdf(k, n, alpha)
    return min(1.0, hoeff, bentkus)


@dataclass
class CertifiedThreshold:
    """A single candidate threshold and its LTT test outcome."""
    threshold: float
    risk: float            # empirical R_hat(lambda) on calibration
    p_value: float         # raw (uncorrected) p-value for H: R > alpha
    certified: bool        # passed the FWER-corrected test at level delta


@dataclass
class LearnThenTestResult:
    """Outcome of :func:`learn_then_test`.

    ``certified`` lists every threshold whose corrected p-value passed: with
    probability >= 1 - delta, ALL of them simultaneously have true risk <= alpha
    (FWER control). ``recommended`` is the operating point we suggest *among the
    certified set*; for an FNR/miss-rate budget the safest recommendation is the
    LARGEST certified threshold (emits the fewest findings while still certified),
    or None if nothing certified.
    """
    candidates: List[CertifiedThreshold]
    certified: List[float]
    recommended: Optional[float]
    alpha: float
    delta: float
    n: int
    correction: str
    p_value_name: str = "hoeffding_bentkus"

    @property
    def feasible(self) -> bool:
        return self.recommended is not None


def learn_then_test(
    calibration: Sequence[CalPair],
    candidates: Sequence[float],
    alpha: float = 0.1,
    risk_fn: str | LossFn = "fnr",
    correction: str = "bonferroni",
    delta: float = 0.1,
    p_value: str = "hoeffding_bentkus",
) -> LearnThenTestResult:
    """Certify thresholds with a high-probability (1 - delta) risk bound via LTT.

    Parameters
    ----------
    calibration:
        ``(confidence, is_true_vulnerability)`` pairs, exchangeable with prod.
    candidates:
        Threshold grid to test (each is a hypothesis H_lambda: R(lambda) > alpha).
    alpha:
        Risk level we want each certified threshold to satisfy.
    risk_fn:
        ``"fnr"`` or a callable ``(lambda, calibration) -> R_hat`` bounded in
        [0, 1]. (Unlike CRC, LTT does NOT require monotonicity for *validity* — any
        family of hypotheses is fair game — though monotone losses interact well
        with the fixed-sequence correction.)
    correction:
        ``"bonferroni"`` (test all, threshold p at delta/m) or ``"fixed_sequence"``
        (test candidates in the given order, stop at the first failure; spends the
        whole budget delta at each step, so it is more powerful when the order is
        informative). Both control FWER at delta.
    delta:
        Family-wise error rate: P(any certified lambda has true risk > alpha)
        <= delta.
    p_value:
        ``"hoeffding_bentkus"`` (default, tighter) or ``"hoeffding"`` (simple).

    Returns
    -------
    LearnThenTestResult

    Guarantee & caveats
    -------------------
    Under exchangeability, with probability at least 1 - delta EVERY threshold in
    the returned ``certified`` set has true risk R(lambda) <= alpha simultaneously
    (Theorem 1 / Bonferroni & fixed-sequence sections of arXiv:2110.01052). This is
    a stronger, high-probability statement than CRC's in-expectation bound, at the
    cost of being more conservative (it certifies fewer thresholds). The p-values
    are valid for losses bounded in [0, 1]; a custom ``risk_fn`` MUST honour that
    range or validity is lost. The ``recommended`` point is the most conservative
    certified threshold for a miss-rate budget (largest lambda => fewest emitted),
    or None if the data cannot certify any threshold at (alpha, delta).
    """
    if risk_fn == "fnr":
        loss_fn: LossFn = fnr_loss
    elif callable(risk_fn):
        loss_fn = risk_fn
    else:
        raise ValueError(f"unknown risk_fn {risk_fn!r}; pass 'fnr' or a callable")

    if p_value == "hoeffding_bentkus":
        pval_fn = hoeffding_bentkus_p_value
    elif p_value == "hoeffding":
        pval_fn = hoeffding_p_value
    else:
        raise ValueError(f"unknown p_value {p_value!r}")

    n = len(calibration)
    cand_list = list(candidates)
    m = len(cand_list)

    rows: List[CertifiedThreshold] = []
    certified: List[float] = []

    if n == 0 or m == 0:
        return LearnThenTestResult([], [], None, alpha, delta, n, correction,
                                   p_value)

    if correction == "bonferroni":
        threshold_p = delta / m
        for lam in cand_list:
            r_hat = loss_fn(lam, calibration)
            p = pval_fn(r_hat, alpha, n)
            ok = p <= threshold_p
            rows.append(CertifiedThreshold(lam, round(r_hat, 6), p, ok))
            if ok:
                certified.append(lam)
    elif correction == "fixed_sequence":
        # Test in the given order, spending the full budget delta at each step;
        # stop at the first non-rejection (a monotone, FWER-valid procedure).
        stopped = False
        for lam in cand_list:
            r_hat = loss_fn(lam, calibration)
            p = pval_fn(r_hat, alpha, n)
            if stopped:
                rows.append(CertifiedThreshold(lam, round(r_hat, 6), p, False))
                continue
            ok = p <= delta
            rows.append(CertifiedThreshold(lam, round(r_hat, 6), p, ok))
            if ok:
                certified.append(lam)
            else:
                stopped = True  # fixed-sequence halts at first failure
    else:
        raise ValueError(
            f"unknown correction {correction!r}; "
            "pass 'bonferroni' or 'fixed_sequence'"
        )

    # Most conservative certified operating point for a miss-rate budget: the
    # largest threshold (emit fewest findings) that is still certified.
    recommended = max(certified) if certified else None

    return LearnThenTestResult(
        candidates=rows,
        certified=certified,
        recommended=recommended,
        alpha=alpha,
        delta=delta,
        n=n,
        correction=correction,
        p_value_name=p_value,
    )


# --------------------------------------------------------------------------- #
# Operator-facing report
# --------------------------------------------------------------------------- #
def report(result: RiskControlResult | LearnThenTestResult) -> str:
    """Human-readable summary that states clearly what IS and ISN'T guaranteed.

    Accepts either a CRC :class:`RiskControlResult` or an LTT
    :class:`LearnThenTestResult`.
    """
    if isinstance(result, RiskControlResult):
        lines = [
            f"Conformal Risk Control ({result.loss} loss)",
            f"  chosen threshold : {result.threshold:.4f}  "
            f"(emit if confidence >= threshold)",
            f"  empirical risk   : {result.achieved_risk:.4f}  "
            f"(raw R_hat on n={result.n} calibration points)",
            f"  CRC bound        : {result.bound:.4f}  "
            f"((n/(n+1))*R_hat + B/(n+1), B={result.B})",
            f"  target alpha     : {result.alpha:.4f}",
        ]
        if result.feasible:
            lines.append(
                "  GUARANTEE        : E[loss] <= alpha on a fresh exchangeable "
                "point (finite-sample, distribution-free; arXiv:2208.02814)."
            )
        else:
            lines.append(
                "  GUARANTEE        : NONE at this alpha -- no threshold met the "
                "budget; returned the most conservative (emit-everything) "
                "fallback. Loosen alpha or collect more/cleaner calibration data."
            )
        return "\n".join(lines)

    # LearnThenTestResult
    lines = [
        f"Learn-then-Test ({result.p_value_name} p-value, "
        f"{result.correction} correction)",
        f"  alpha (risk)     : {result.alpha:.4f}",
        f"  delta (FWER)     : {result.delta:.4f}",
        f"  n calibration    : {result.n}",
        f"  tested           : {len(result.candidates)} thresholds; "
        f"certified {len(result.certified)}",
    ]
    if result.recommended is not None:
        lines.append(
            f"  recommended      : {result.recommended:.4f}  "
            "(largest certified threshold => fewest emitted, safest miss-rate "
            "posture)"
        )
        lines.append(
            "  GUARANTEE        : with prob >= 1 - delta, ALL certified "
            "thresholds have true risk <= alpha (FWER controlled; "
            "arXiv:2110.01052)."
        )
    else:
        lines.append(
            "  recommended      : NONE -- no threshold could be certified at "
            "(alpha, delta). The data are insufficient to claim risk <= alpha "
            "with confidence 1 - delta; loosen alpha/delta or add calibration "
            "data."
        )
    return "\n".join(lines)
