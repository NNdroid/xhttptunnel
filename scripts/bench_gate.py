#!/usr/bin/env python3
"""Fail CI when a benchmark regresses beyond a threshold.

Compares two `go test -bench` text outputs (baseline vs current) and exits
non-zero when a benchmark regresses by more than the threshold ratio.

The decision statistic is the **minimum** ns/op by default: the run-to-run
floor. On shared CI runners the per-count mean is dominated by transient
GC/scheduler/noisy-neighbour spikes, so identical code can "regress" ~1.5x on
the mean alone (observed: ThroughCDN). A genuine algorithmic regression (e.g.
the 2s-close stall, the CDN buffering stall) also lifts the floor, so min
still catches it while ignoring single-iteration noise. Choose the statistic
with --stat {min,mean,median}.

The pass/fail decision is made here, on the stable `go test` output format,
rather than by parsing benchstat's table (whose layout has changed across
versions). benchstat is still run in the workflow for the human-readable log.

Usage: bench_gate.py BASE_FILE NEW_FILE [--threshold 1.25] [--stat min]
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


def _stat(name):
    if name == "min":
        return min
    if name == "median":
        return statistics.median
    return statistics.fmean  # "mean"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("new")
    ap.add_argument(
        "--threshold",
        type=float,
        default=1.25,
        help="fail when new <stat> ns/op exceeds base by this ratio (default 1.25 = +25%%)",
    )
    ap.add_argument(
        "--stat",
        choices=("min", "mean", "median"),
        default="min",
        help="per-benchmark statistic compared (default min: robust to CI noise)",
    )
    args = ap.parse_args()
    agg = _stat(args.stat)

    base = parse(args.base)
    new = parse(args.new)

    common = sorted(set(base) & set(new))

    if not common:
        # Nothing to compare (e.g. benchmark set changed wholesale). Do not
        # fail the build on a gate that has no signal.
        print("bench_gate: no common benchmarks between base and new; skipping gate")
        for name in sorted(set(base) - set(new)):
            print(f"  removed: {name}")
        for name in sorted(set(new) - set(base)):
            print(f"  added:   {name}")
        return 0

    regressions = []
    print(f"{'benchmark':<48} {'base ns/op':>14} {'new ns/op':>14} {'ratio':>8}   (mean base→new)")
    for name in common:
        b = agg(base[name])
        n = agg(new[name])
        ratio = n / b if b else float("inf")
        flag = "  REGRESSION" if ratio > args.threshold else ""
        bm, nm = statistics.fmean(base[name]), statistics.fmean(new[name])
        print(
            f"{name:<48} {b:>14.2f} {n:>14.2f} {ratio:>7.2f}x{flag}   ({bm:.0f}→{nm:.0f})"
        )
        if ratio > args.threshold:
            regressions.append((name, b, n, ratio))

    for name in sorted(set(new) - set(base)):
        print(f"{name:<48} {'(new)':>14}")
    for name in sorted(set(base) - set(new)):
        print(f"{name:<48} {'(removed)':>14}")

    if regressions:
        print(
            f"\nbench_gate: {len(regressions)} benchmark(s) regressed beyond "
            f"{args.threshold:.2f}x {args.stat} ns/op:",
            file=sys.stderr,
        )
        for name, b, n, ratio in regressions:
            print(f"  {name}: {b:.2f} -> {n:.2f} ns/op ({ratio:.2f}x)", file=sys.stderr)
        print(
            "\nIf this is intentional, raise BENCH_THRESHOLD, run more counts, "
            "or re-run against a newer baseline.",
            file=sys.stderr,
        )
        return 1

    print(f"\nbench_gate: OK (stat={args.stat}, threshold {args.threshold:.2f}x)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
