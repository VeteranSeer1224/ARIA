"""Spec-alignment checks for the benchmark metrics (#8) and the architectural
baseline dispatch (#9). Offline, no LLM and no chromadb:

    python tests/test_evaluation_metrics.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ml.evaluation import (
    MetricsCalculator, Scorer, BenchmarkEnvironment, ConditionRunner,
)


def test_ttc_none_when_no_compromise():
    assert MetricsCalculator.calculate_ttc(0.0, None) is None
    assert MetricsCalculator.calculate_ttc(10.0, 160.0) == 150.0


def test_asc_counts_vulnerabilities_not_nodes():
    scorer = Scorer(BenchmarkEnvironment())
    # web plants 2 vulnerabilities; identifying 1 -> ASC 0.5, independent of nodes.
    data = {
        "objectives_completed": 1, "vulnerabilities_identified": 1,
        "start_time": 0.0, "compromise_time": 100.0,
        "unproductive_invocations": 0, "total_invocations": 1, "findings": [],
    }
    assert scorer.score_run(data, "web")["ASC"] == 0.5


def test_tcr_denominator_is_defined_objectives():
    scorer = Scorer(BenchmarkEnvironment())
    # e2e defines 2 objectives; completing 1 -> TCR 0.5 even when the live run
    # tracked fewer tasks (replanning must not shrink the denominator).
    data = {
        "objectives_completed": 1, "vulnerabilities_identified": 1,
        "start_time": 0.0, "compromise_time": None,
        "unproductive_invocations": 3, "total_invocations": 4, "findings": [],
    }
    scores = scorer.score_run(data, "e2e")
    assert scores["TCR"] == 0.5
    assert scores["TTC"] is None


def test_far_is_invocation_ratio():
    assert MetricsCalculator.calculate_far(3, 4) == 0.75


def test_condition_runner_dispatches_distinct_architectures():
    calls = []
    mono = lambda c, s: calls.append(("mono", c)) or {}
    hier = lambda c, s: calls.append(("hier", c)) or {}
    runner = ConditionRunner(monolithic_runner=mono, hierarchical_runner=hier)
    runner("baseline", "web")
    runner("aria_base", "web")
    runner("aria_tuned", "web")
    assert calls == [("mono", "baseline"), ("hier", "aria_base"), ("hier", "aria_tuned")]


def test_condition_runner_refuses_baseline_through_aria_pipeline():
    runner = ConditionRunner(hierarchical_runner=lambda c, s: {})
    try:
        runner("baseline", "web")
    except NotImplementedError:
        pass
    else:
        raise AssertionError("baseline must not silently run through the ARIA pipeline")


if __name__ == "__main__":
    test_ttc_none_when_no_compromise()
    test_asc_counts_vulnerabilities_not_nodes()
    test_tcr_denominator_is_defined_objectives()
    test_far_is_invocation_ratio()
    test_condition_runner_dispatches_distinct_architectures()
    test_condition_runner_refuses_baseline_through_aria_pipeline()
    print("ok")
