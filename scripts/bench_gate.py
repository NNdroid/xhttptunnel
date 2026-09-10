#!/usr/bin/env python3
"""Fail CI when a benchmark regresses beyond a threshold.

Compares two `go test -bench` text outputs (baseline vs current) by the mean
ns/op of each benchmark and exits non-zero when any benchmark's mean grew by
more than the threshold ratio.

The pass/fail decision is made here, on the stable `go test` output format,
rather than by parsing benchstat's table (whose layout has changed across
versions). benchstat is still run in the workflow for the human-readable log.

Usage: bench_gate.py BASE_FILE NEW_FILE [--threshold 1.25]
"""
import argparse
import re
import statistics
import sys

# BenchmarkName-8   1000000   245.1 ns/op   1024 B/op   16 allocs/op
# The time column is the first "<number> <unit>/op"; capture name, value, unit.
BENCH_RE = re.compile(
    r"^(?P<name>Benchmark\S+)\s+\d+\s+(?P<value>[\d.]+)\s+(?P<unit>ns|µs|us|ms|s)/op"
)

UNIT_TO_NS = {"ns": 1.0, "µs": 1e3, "us": 1e3, "ms": 1e6, "s": 1e9}


def parse(path):
    """Return {benchmark_name: [ns_per_op, ...]} from a go test bench file."""
    samples = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = BENCH_RE.match(line.strip())
            if not m:
                continue
            ns = float(m.group("value")) * UNIT_TO_NS[m.group("unit")]
            samples.setdefault(m.group("name"), []).append(ns)
    return samples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("new")
    ap.add_argument(
        "--threshold",
        type=float,
        default=1.25,
        help="fail when new mean ns/op exceeds base mean by this ratio (default 1.25 = +25%%)",
    )
    args = ap.parse_args()

    base = parse(args.base)
    new = parse(args.new)

    common = sorted(set(base) & set(new))
    only_base = sorted(set(base) - set(new))
    only_new = sorted(set(new) - set(base))

    if not common:
        # Nothing to compare (e.g. benchmark set changed wholesale). Do not
        # fail the build on a gate that has no signal.
        print("bench_gate: no common benchmarks between base and new; skipping gate")
        for name in only_base:
            print(f"  removed: {name}")
        for name in only_new:
            print(f"  added:   {name}")
        return 0

    regressions = []
    print(f"{'benchmark':<48} {'base ns/op':>14} {'new ns/op':>14} {'ratio':>8}")
    for name in common:
        b = statistics.fmean(base[name])
        n = statistics.fmean(new[name])
        ratio = n / b if b else float("inf")
        flag = "  REGRESSION" if ratio > args.threshold else ""
        print(f"{name:<48} {b:>14.2f} {n:>14.2f} {ratio:>7.2f}x{flag}")
        if ratio > args.threshold:
            regressions.append((name, b, n, ratio))

    for name in only_new:
        print(f"{name:<48} {'(new)':>14}")
    for name in only_base:
        print(f"{name:<48} {'(removed)':>14}")

    if regressions:
        print(
            f"\nbench_gate: {len(regressions)} benchmark(s) regressed beyond "
            f"{args.threshold:.2f}x mean ns/op:",
            file=sys.stderr,
        )
        for name, b, n, ratio in regressions:
            print(f"  {name}: {b:.2f} -> {n:.2f} ns/op ({ratio:.2f}x)", file=sys.stderr)
        print(
            "\nIf this is intentional, raise BENCH_THRESHOLD or re-run against a "
            "newer baseline.",
            file=sys.stderr,
        )
        return 1

    print(f"\nbench_gate: OK (threshold {args.threshold:.2f}x)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
