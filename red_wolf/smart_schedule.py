"""
smart_schedule.py
------------------
Concrete application of rwo.py inside Red Wolf: instead of testing the
wordlist in plain alphabetical order, use Red Wolf Optimization to learn
WHICH PATH CATEGORY to prioritize first, so real findings are (on
average) discovered after fewer requests -- useful when a scan is rate
limited or time-boxed and won't necessarily finish the whole wordlist.

How the optimization problem is framed:
  - "Position" X = a 4-dim weight vector [w_api, w_admin, w_file, w_misc].
  - Categories get tested in descending order of their weight.
  - Fitness(X) = expected number of requests sent, on average, before
    hitting a real vulnerable endpoint -- LOWER is better.
  - VULNERABLE_PRIOR below is an ILLUSTRATIVE prior (not a measured
    statistic) reflecting the common intuition in bug bounty hunting
    that exposed REST APIs are more frequently the source of broken
    access control findings than, say, leftover misc/config paths.
    Override it with your own numbers if you have real data for a
    given target's tech stack.
"""

from typing import Dict, List, Optional, Tuple

import numpy as np

from .rwo import minimize
from .wordlists import API_PATHS, ADMIN_PATHS, FILE_PATHS, MISC_PATHS

CATEGORY_PATHS: Dict[str, List[str]] = {
    "api": API_PATHS,
    "admin": ADMIN_PATHS,
    "file": FILE_PATHS,
    "misc": MISC_PATHS,
}
CATEGORY_ORDER = ["api", "admin", "file", "misc"]  # fixed index order used for weight vectors

# Illustrative prior: "if there's an unauthenticated-access bug somewhere
# in this target, how likely is it to live in each category?"
VULNERABLE_PRIOR = {
    "api": 0.55,
    "file": 0.30,
    "admin": 0.10,
    "misc": 0.05,
}


def _expected_position(order: List[str]) -> float:
    """
    Given a category visiting order (e.g. ["api","file","admin","misc"]),
    compute the expected number of requests sent before hitting a
    vulnerable endpoint, weighted by VULNERABLE_PRIOR and each
    category's real size from wordlists.py.
    """
    expected = 0.0
    requests_before = 0
    for cat in order:
        size = len(CATEGORY_PATHS[cat])
        # If the vuln is in this category, expected position is halfway through it.
        expected += VULNERABLE_PRIOR[cat] * (requests_before + (size + 1) / 2.0)
        requests_before += size
    return expected


def _weights_to_order(weights: np.ndarray) -> List[str]:
    ranked = sorted(zip(CATEGORY_ORDER, weights), key=lambda kv: -kv[1])
    return [cat for cat, _ in ranked]


def _fitness(weights: np.ndarray) -> float:
    return _expected_position(_weights_to_order(weights))


def learn_category_priority(n_wolves: int = 20, max_iter: int = 40, seed: int = 7) -> Tuple[List[str], float]:
    """
    Run RWO to find the category weight vector that minimizes expected
    requests-to-first-finding. Returns (best_order, expected_requests).
    """
    result = minimize(
        fitness_fn=_fitness,
        dim=len(CATEGORY_ORDER),
        bounds=(0.0, 1.0),
        n_wolves=n_wolves,
        max_iter=max_iter,
        seed=seed,
    )
    best_order = _weights_to_order(result.best_position)
    return best_order, result.best_fitness


def baseline_alphabetical_expected_position() -> float:
    """
    The "naive" baseline Red Wolf used to use: the full wordlist sorted
    alphabetically as one flat list (see wordlists.DEFAULT_WORDLIST),
    which interleaves categories essentially arbitrarily.
    """
    from .wordlists import DEFAULT_WORDLIST
    tagged = []
    for path in DEFAULT_WORDLIST:
        for cat, paths in CATEGORY_PATHS.items():
            if path in paths:
                tagged.append(cat)
                break
    expected = 0.0
    for cat, prior in VULNERABLE_PRIOR.items():
        positions = [i for i, c in enumerate(tagged) if c == cat]
        avg_pos = sum(positions) / len(positions) if positions else 0
        expected += prior * avg_pos
    return expected


def build_prioritized_wordlist(order: Optional[List[str]] = None) -> List[str]:
    """
    Return the full wordlist re-ordered so that higher-priority
    categories (per `order`, or the RWO-learned order if not given)
    come first. Paths keep their original relative order within
    their own category.
    """
    if order is None:
        order, _ = learn_category_priority()
    out = []
    for cat in order:
        out.extend(CATEGORY_PATHS[cat])
    return out
