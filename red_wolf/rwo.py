"""
rwo.py
------
Red Wolf Optimization (RWO) -- a Grey-Wolf-Optimizer-style meta-heuristic,
implemented exactly per the math it was derived from:

    Leaders: alpha (best) and beta (second-best) solutions found so far.
    Caution coefficient:   A = 2*a*r1 - a         (a decays linearly 2 -> 0)
    Distance to leaders:   D_alpha = |C1*X_alpha - X|
                            D_beta  = |C2*X_beta  - X|
    Candidate directions:  X1 = X_alpha - A1*D_alpha
                            X2 = X_beta  - A2*D_beta
    Position update:       X(t+1) = (X1 + X2) / 2

|A| > 1  -> exploration (wolves diverge to search new areas)
|A| < 1  -> exploitation (wolves converge on the best-known area)

This is a GENERIC numerical optimizer: minimize(fitness_fn, dim, bounds).
It knows nothing about endpoints, scanning, or security -- that mapping
lives in smart_schedule.py, which uses this as a black-box minimizer.
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Callable, List, Tuple


@dataclass
class RWOResult:
    best_position: np.ndarray
    best_fitness: float
    convergence: List[float] = field(default_factory=list)  # best fitness per iteration


def minimize(
    fitness_fn: Callable[[np.ndarray], float],
    dim: int,
    bounds: Tuple[float, float] = (0.0, 1.0),
    n_wolves: int = 20,
    max_iter: int = 50,
    seed: int = 42,
) -> RWOResult:
    """
    Minimize fitness_fn over an n-dimensional continuous search space.

    fitness_fn: takes a 1D numpy array of length `dim`, returns a scalar
                (lower = better).
    bounds:     (low, high) applied to every dimension.
    n_wolves:   population size.
    max_iter:   number of learning iterations.
    """
    rng = np.random.default_rng(seed)
    low, high = bounds

    # Initialize the pack randomly within bounds.
    positions = rng.uniform(low, high, size=(n_wolves, dim))
    fitness = np.array([fitness_fn(w) for w in positions])

    convergence = []

    for t in range(max_iter):
        # a decays linearly from 2 to 0 across iterations -- this is what
        # shifts the pack from exploration (early) to exploitation (late).
        a = 2.0 - 2.0 * (t / max_iter)

        # Identify the leading pair: alpha (best) and beta (second-best).
        order = np.argsort(fitness)
        alpha_pos, beta_pos = positions[order[0]].copy(), positions[order[1]].copy()

        new_positions = np.empty_like(positions)
        for i in range(n_wolves):
            r1 = rng.random(dim)
            A1 = 2 * a * r1 - a
            C1 = 2 * rng.random(dim)  # "camouflage"/obstacle coefficient
            D_alpha = np.abs(C1 * alpha_pos - positions[i])
            X1 = alpha_pos - A1 * D_alpha

            r1b = rng.random(dim)
            A2 = 2 * a * r1b - a
            C2 = 2 * rng.random(dim)
            D_beta = np.abs(C2 * beta_pos - positions[i])
            X2 = beta_pos - A2 * D_beta

            new_positions[i] = np.clip((X1 + X2) / 2.0, low, high)

        positions = new_positions
        fitness = np.array([fitness_fn(w) for w in positions])
        convergence.append(float(fitness.min()))

    best_idx = int(np.argmin(fitness))
    return RWOResult(best_position=positions[best_idx], best_fitness=float(fitness[best_idx]), convergence=convergence)
