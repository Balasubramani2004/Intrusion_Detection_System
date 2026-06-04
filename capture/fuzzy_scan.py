"""
Mamdani-style fuzzy port-scan scoring for ScanTracker metrics.

Default install: FUZZY_SCAN_ENABLED=False in config — ScanTracker behavior is unchanged.
When enabled with FUZZY_SCAN_EXPLAIN_ONLY=True (default), alerts use the same crisp
thresholds; fuzzy output is attached as fuzzy_rule / fuzzy_score for display only.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


def _tri(x: float, a: float, b: float, c: float) -> float:
    if x <= a or x >= c:
        return 0.0
    if b <= a or c <= b:
        return 0.0
    if x == b:
        return 1.0
    if x < b:
        return (x - a) / (b - a)
    return (c - x) / (c - b)


def _gauss(x: float, center: float, sigma: float) -> float:
    sigma = max(sigma, 1e-6)
    return math.exp(-0.5 * ((x - center) / sigma) ** 2)


@dataclass(frozen=True)
class _Term:
    low: float
    mid: float
    high: float

    def mu(self, x: float, label: str) -> float:
        x = max(0.0, min(1.0, float(x)))
        if label == "LOW":
            return _tri(x, 0.0, 0.0, self.low)
        if label == "MEDIUM":
            return _tri(x, self.low, self.mid, self.high)
        if label == "HIGH":
            return _tri(x, self.mid, 1.0, 1.0)
        return 0.0


# Normalized inputs in [0, 1]
_PORTS = _Term(0.25, 0.55, 0.85)
_SYN = _Term(0.20, 0.50, 0.80)
_SYN_FRAC = _Term(0.35, 0.65, 0.90)
_RATE = _Term(0.20, 0.50, 0.85)


@dataclass
class _Rule:
    name: str
    antecedents: Tuple[Tuple[str, str], ...]
    consequent: float
    rule_text: str


_RULES: List[_Rule] = [
    _Rule(
        "R1_burst_scan",
        (("ports", "HIGH"), ("syn_frac", "HIGH"), ("rate", "HIGH")),
        0.95,
        "IF unique_ports IS HIGH AND syn_fraction IS HIGH AND port_rate IS HIGH "
        "THEN port_scan_risk IS VERY_HIGH",
    ),
    _Rule(
        "R2_syn_sweep",
        (("ports", "HIGH"), ("syn_frac", "HIGH")),
        0.90,
        "IF unique_ports IS HIGH AND syn_fraction IS HIGH THEN port_scan_risk IS HIGH",
    ),
    _Rule(
        "R3_fast_probe",
        (("ports", "MEDIUM"), ("rate", "HIGH"), ("syn", "MEDIUM")),
        0.82,
        "IF unique_ports IS MEDIUM AND port_rate IS HIGH AND syn_events IS MEDIUM "
        "THEN port_scan_risk IS HIGH",
    ),
    _Rule(
        "R4_local_target",
        (("ports", "MEDIUM"), ("local", "HIGH"), ("syn_frac", "MEDIUM")),
        0.88,
        "IF unique_ports IS MEDIUM AND victim_is_local IS HIGH AND syn_fraction IS MEDIUM "
        "THEN port_scan_risk IS HIGH",
    ),
    _Rule(
        "R5_window_scan",
        (("ports", "MEDIUM"), ("syn", "MEDIUM")),
        0.75,
        "IF unique_ports IS MEDIUM AND syn_events IS MEDIUM THEN port_scan_risk IS MEDIUM",
    ),
    _Rule(
        "R6_weak_signal",
        (("ports", "LOW"), ("syn_frac", "LOW")),
        0.15,
        "IF unique_ports IS LOW AND syn_fraction IS LOW THEN port_scan_risk IS LOW",
    ),
    _Rule(
        "R7_mixed",
        (("ports", "LOW"), ("rate", "HIGH")),
        0.45,
        "IF unique_ports IS LOW AND port_rate IS HIGH THEN port_scan_risk IS MEDIUM",
    ),
    _Rule(
        "R8_background",
        (("ports", "LOW"), ("syn", "LOW")),
        0.05,
        "IF unique_ports IS LOW AND syn_events IS LOW THEN port_scan_risk IS VERY_LOW",
    ),
]


def _normalize_metrics(
    *,
    unique_ports: int,
    syn_events: int,
    total_events: int,
    span_sec: float,
    victim_is_local: bool,
) -> Dict[str, float]:
    total = max(1, int(total_events))
    span = max(0.5, float(span_sec))
    ports_n = min(1.0, unique_ports / 24.0)
    syn_n = min(1.0, syn_events / 16.0)
    syn_frac = min(1.0, syn_events / total)
    rate_n = min(1.0, unique_ports / span / 6.0)
    local_n = 1.0 if victim_is_local else 0.0
    return {
        "ports": ports_n,
        "syn": syn_n,
        "syn_frac": syn_frac,
        "rate": rate_n,
        "local": local_n,
    }


def _mu_for_term(metric: str, label: str, values: Dict[str, float]) -> float:
    x = values.get(metric, 0.0)
    if metric == "local":
        if label == "HIGH":
            return _gauss(x, 1.0, 0.25)
        if label == "MEDIUM":
            return _gauss(x, 0.5, 0.30)
        if label == "LOW":
            return _gauss(x, 0.0, 0.25)
        return 0.0
    table = {
        "ports": _PORTS,
        "syn": _SYN,
        "syn_frac": _SYN_FRAC,
        "rate": _RATE,
    }.get(metric)
    if table is None:
        return 0.0
    return table.mu(x, label)


class FuzzyScanEvaluator:
    """Sugeno-style aggregation over hand-tuned port-scan rules."""

    def evaluate(
        self,
        *,
        unique_ports: int,
        syn_events: int,
        total_events: int,
        span_sec: float,
        victim_is_local: bool = False,
        detection_mode: str = "",
    ) -> Dict[str, Any]:
        values = _normalize_metrics(
            unique_ports=unique_ports,
            syn_events=syn_events,
            total_events=total_events,
            span_sec=span_sec,
            victim_is_local=victim_is_local,
        )

        strengths: List[Tuple[float, _Rule]] = []
        for rule in _RULES:
            firing = 1.0
            for metric, term in rule.antecedents:
                firing = min(firing, _mu_for_term(metric, term, values))
            if firing > 0.01:
                strengths.append((firing, rule))

        if not strengths:
            return {
                "score": 0.0,
                "rule": "",
                "top_rule": "",
                "metrics": values,
                "detection_mode": detection_mode,
            }

        num = sum(w * r.consequent for w, r in strengths)
        den = sum(w for w, _ in strengths)
        score = num / den if den > 0 else 0.0
        top_w, top_rule = max(strengths, key=lambda t: t[0] * t[1].consequent)

        return {
            "score": round(min(1.0, max(0.0, score)), 4),
            "rule": top_rule.rule_text,
            "top_rule": top_rule.name,
            "rule_strength": round(top_w, 4),
            "metrics": values,
            "detection_mode": detection_mode,
        }


_DEFAULT_EVALUATOR = FuzzyScanEvaluator()


def evaluate_port_scan_fuzzy(
    *,
    unique_ports: int,
    syn_events: int,
    total_events: int,
    span_sec: float,
    victim_is_local: bool = False,
    detection_mode: str = "",
) -> Dict[str, Any]:
    return _DEFAULT_EVALUATOR.evaluate(
        unique_ports=unique_ports,
        syn_events=syn_events,
        total_events=total_events,
        span_sec=span_sec,
        victim_is_local=victim_is_local,
        detection_mode=detection_mode,
    )
