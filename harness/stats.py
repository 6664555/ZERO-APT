"""harness/stats.py - pure-Python implementation of the paper appendix statistical tests (zero external deps)

Tests used in the Appendix (Statistical Test Details):
- chi2_yates  : 2x2 chi-square (Yates continuity correction) -> H1 per-scheme ASR comparisons
- welch_t     : Welch's t-test (heteroscedastic) -> H2/H3/H4/H6/H7
- friedman    : Friedman test (repeated measures) -> H5 overall tier difference
- pages_l     : Page's L test (ordered alternative) -> H5 linear trend
- holm        : Holm-Bonferroni correction
- cohen_d     : effect size

p-values are computed via continued-fraction expansions of the incomplete gamma/beta functions
(Numerical Recipes method), matching scipy to normal precision; callable directly after the
1,400-experiment data is produced.
"""

import math

EPS = 1e-15
MAX_ITER = 200


# ---- Distribution functions ----

def _gammainc_lower(a, x):
    """Regularized lower incomplete gamma function P(a, x)."""
    if x < 0 or a <= 0:
        raise ValueError("invalid args")
    if x < a + 1.0:
        # series expansion
        ap, s, d = a, 1.0 / a, 1.0 / a
        for _ in range(MAX_ITER):
            ap += 1.0
            d *= x / ap
            s += d
            if abs(d) < abs(s) * EPS:
                return s * math.exp(-x + a * math.log(x) - math.lgamma(a))
        raise RuntimeError("gamma series did not converge")
    # continued-fraction expansion
    b = x + 1.0 - a
    c = 1.0 / EPS
    d = 1.0 / b
    h = d
    for i in range(1, MAX_ITER + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < EPS:
            d = EPS
        c = b + an / c
        if abs(c) < EPS:
            c = EPS
        d = 1.0 / d
        del_ = d * c
        h *= del_
        if abs(del_ - 1.0) < EPS:
            return 1.0 - math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    raise RuntimeError("gamma CF did not converge")


def _betacf(a, b, x):
    """Incomplete beta function continued fraction (Numerical Recipes betacf, Lentz's algorithm)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < EPS:
        d = EPS
    d = 1.0 / d
    h = d
    for m in range(1, MAX_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < EPS:
            d = EPS
        c = 1.0 + aa / c
        if abs(c) < EPS:
            c = EPS
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < EPS:
            d = EPS
        c = 1.0 + aa / c
        if abs(c) < EPS:
            c = EPS
        d = 1.0 / d
        del_ = d * c
        h *= del_
        if abs(del_ - 1.0) < EPS:
            return h
    raise RuntimeError("beta CF did not converge")


def _betainc(a, b, x):
    """Regularized incomplete beta function I_x(a, b) (Numerical Recipes betai)."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    front = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                     + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def chi2_p(df, x):
    """Chi-square survival function (right-tail probability). df = degrees of freedom, x >= 0."""
    return 1.0 - _gammainc_lower(df / 2.0, x / 2.0) if x > 0 else 1.0


def t_p(df, t):
    """Two-sided p-value of the t distribution. df > 0."""
    x = df / (df + t * t)
    return _betainc(df / 2.0, 0.5, x) if x < 1 else 0.0


# ---- Test functions (appendix definitions) ----

def chi2_yates(table):
    """2x2 chi-square test (Yates continuity correction). table = [[a, b], [c, d]].

    Returns (statistic, p, phi). phi is the effect size.
    """
    ((a, b), (c, d)) = table
    n = a + b + c + d
    if n == 0:
        return (0.0, 1.0, 0.0)
    num = abs(a * d - b * c) - n / 2.0
    num = max(num, 0.0)  # Yates-corrected negative -> 0
    stat = n * num * num / ((a + b) * (c + d) * (a + c) * (b + d))
    p = chi2_p(1, stat)
    phi = math.sqrt(stat / n)
    return (stat, p, phi)


def welch_t(a, b):
    """Welch's t-test (two-sided, heteroscedastic). Returns (t, df, p, cohen_d)."""
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return (0.0, 0.0, 1.0, 0.0)
    m1 = sum(a) / n1
    m2 = sum(b) / n2
    v1 = sum((x - m1) ** 2 for x in a) / (n1 - 1)
    v2 = sum((x - m2) ** 2 for x in b) / (n2 - 1)
    se = math.sqrt(v1 / n1 + v2 / n2)
    if se == 0:
        return (0.0, n1 + n2 - 2, 1.0, 0.0)
    t = (m1 - m2) / se
    df = (v1 / n1 + v2 / n2) ** 2 / ((v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1))
    # effect size: pooled-standard-deviation Cohen's d
    sp = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
    d = (m1 - m2) / sp if sp else 0.0
    return (t, df, t_p(df, t), d)


def friedman(matrix):
    """Friedman test (repeated measures). matrix = list of lists: rows=subjects, cols=conditions.

    Returns (chi2_stat, p). Paper H5: overall difference of per-scheme x three-tier ASR.
    """
    k = len(matrix[0]) if matrix else 0
    n = len(matrix)
    if n < 2 or k < 2:
        return (0.0, 1.0)
    ranks = []
    for row in matrix:
        order = sorted(range(k), key=lambda i: row[i])
        r = [0.0] * k
        i = 0
        while i < k:
            j = i
            while j + 1 < k and row[order[j + 1]] == row[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for m in range(i, j + 1):
                r[order[m]] = avg
            i = j + 1
        ranks.append(r)
    col_sums = [sum(ranks[i][j] for i in range(n)) for j in range(k)]
    stat = 12.0 * sum((s - n * (k + 1) / 2.0) ** 2 for s in col_sums) / (n * k * (k + 1))
    return (stat, chi2_p(k - 1, stat))


def pages_l(matrix):
    """Page's L test (ordered alternative: linear trend across conditions). matrix as in friedman.

    Returns (L, p). p uses the normal approximation (large sample); small samples can look up a
    table (approximated here and noted).
    """
    k = len(matrix[0]) if matrix else 0
    n = len(matrix)
    if n < 2 or k < 2:
        return (0.0, 1.0)
    L = 0.0
    for row in matrix:
        order = sorted(range(k), key=lambda i: row[i])
        r = [0.0] * k
        i = 0
        while i < k:
            j = i
            while j + 1 < k and row[order[j + 1]] == row[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for m in range(i, j + 1):
                r[order[m]] = avg
            i = j + 1
        L += sum((j + 1) * r[j] for j in range(k))
    mu = n * k * (k + 1) ** 2 / 4.0
    var = n * (k ** 3 - k) ** 2 / (144.0 * (k - 1))
    z = (L - mu) / math.sqrt(var) if var else 0.0
    # normal-approximation two-sided p
    p = math.erfc(abs(z) / math.sqrt(2.0))
    return (L, p)


def wilcoxon(a, b):
    """Wilcoxon signed-rank test (paired samples, two-sided, normal approximation).

    Paper appendix (Statistical Test Details): Holm-corrected pairwise post-hoc comparisons.
    Returns (W_plus, z, p). Small samples (n<10) have limited normal-approximation precision; p is indicative.
    """
    diffs = [x - y for x, y in zip(a, b)]
    nonzero = [d for d in diffs if d != 0]
    n = len(nonzero)
    if n == 0:
        return (0.0, 0.0, 1.0)
    order = sorted(range(n), key=lambda i: abs(nonzero[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(nonzero[order[j + 1]]) == abs(nonzero[order[i]]):
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for m in range(i, j + 1):
            ranks[order[m]] = avg
        i = j + 1
    w_plus = sum(r for r, d in zip(ranks, nonzero) if d > 0)
    mu = n * (n + 1) / 4.0
    var = n * (n + 1) * (2 * n + 1) / 24.0
    z = (w_plus - mu) / math.sqrt(var) if var else 0.0
    p = math.erfc(abs(z) / math.sqrt(2.0))
    return (w_plus, z, p)


def holm(pvalues, alpha=0.05):
    """Holm-Bonferroni correction. Input [(name, p), ...], returns [(name, p, rejected), ...]."""
    ordered = sorted(pvalues, key=lambda x: x[1])
    m = len(ordered)
    out = {}
    for i, (name, p) in enumerate(ordered):
        threshold = alpha / (m - i)
        out[name] = (p, p < threshold)
    return [(name, p, rejected) for name, (p, rejected) in out.items()]


def cohen_d(a, b):
    """Cohen's d (pooled standard deviation)."""
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0
    m1, m2 = sum(a) / n1, sum(b) / n2
    v1 = sum((x - m1) ** 2 for x in a) / (n1 - 1)
    v2 = sum((x - m2) ** 2 for x in b) / (n2 - 1)
    sp = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
    return (m1 - m2) / sp if sp else 0.0
