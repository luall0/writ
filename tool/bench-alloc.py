#!/usr/bin/env python3
"""make bench-alloc: what the wiping allocator costs (M5.7,
docs/history/m5.7-memory-wiped-on-free.md).

1. Builds the binaries in release, as they ship (target/bench/wiping), and `writd` again without
   the wiping allocator (`--features writd/system-allocator`, target/bench/system): two
   directories of binaries that differ only by `writd`'s allocator.
2. Builds the benchmark (crates/writ-integration/tests/alloc_bench.rs) in release.
3. Runs the in-process paths once (each sample taken both ways, interleaved), then the daemon
   under heavy load `--runs` times per build, alternating which build goes first.
4. Prints the medians (and the latencies' p50 and p99, over every run's samples), and writes
   them with every run's numbers under target/bench/results/.

    python3 -I tool/bench-alloc.py [--runs N] [--skip-micro] [--skip-daemon] [--linux]

`--linux` runs the same in a Linux container (the Rust image `e2e/Dockerfile` pins, glibc's
allocator, as in detached mode): its build in a Docker volume of its own, its results under
target/bench/results-linux/.
"""

import argparse
import json
import os
import pathlib
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BENCH = ROOT / "target" / "bench"
BUILDS = ("system", "wiping")


def cargo(target: str, *args: str) -> str:
    env = dict(os.environ, CARGO_TARGET_DIR=str(BENCH / target))
    return subprocess.run(
        ["cargo", *args], cwd=ROOT, env=env, check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def build() -> pathlib.Path:
    """The two directories of binaries, and the benchmark's test binary."""
    cargo("wiping", "build", "--locked", "--release", "-q", "-p", "writd", "-p", "writ-cli",
          "-p", "writ-sign")
    cargo("system", "build", "--locked", "--release", "-q", "-p", "writd",
          "--features", "writd/system-allocator")
    for name in BUILDS:
        bins = BENCH / "bins" / name
        bins.mkdir(parents=True, exist_ok=True)
        for binary in ("writ", "writ-sign"):
            shutil.copy2(BENCH / "wiping" / "release" / binary, bins / binary)
        shutil.copy2(BENCH / name / "release" / "writd", bins / "writd")
    out = cargo("harness", "test", "--locked", "--release", "-q", "-p", "writ-integration",
                "--test", "alloc_bench", "--no-run", "--message-format=json")
    executables = [json.loads(line).get("executable") for line in out.splitlines()]
    executables = [e for e in executables if e]
    if len(executables) != 1:
        sys.exit(f"bench-alloc: expected one benchmark binary, got {executables}")
    return pathlib.Path(executables[0])


def run(executable: pathlib.Path, test: str, out: pathlib.Path, build: str = "") -> dict:
    env = dict(os.environ, WRIT_BENCH_OUT=str(out), WRIT_BENCH_BUILD=build,
               WRIT_BIN_DIR=str(BENCH / "bins" / (build or "wiping")), RUST_BACKTRACE="0")
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    subprocess.run([str(executable), "--ignored", "--exact", test, "--test-threads=1"],
                   cwd=ROOT / "crates" / "writ-integration", env=env, check=True,
                   stdout=subprocess.DEVNULL)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    numbers = json.loads(out.read_text())
    # Every process of the run, waited for: the daemon and its own processes (hooks, relays,
    # git), the agents' writ, git and ssh, the benchmark itself.
    numbers["cpu_all_s"] = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    out.write_text(json.dumps(numbers, indent=2))
    return numbers


def percentile(samples: list, p: float) -> float:
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, round(p / 100 * len(ordered) + 0.5) - 1))
    return ordered[rank]


def cost(base: float, wiping: float, higher_is_better: bool = False) -> str:
    """What wiping costs, in percent of the system allocator's number: positive is worse."""
    if not base:
        return "n/a"
    change = (wiping - base) / base * 100
    return f"{-change if higher_is_better else change:+.1f} %"


def micro_report(micro: dict) -> list:
    lines = ["| Path (median time of one run) | System | Wiping | Cost of wiping |",
             "|---|---:|---:|---:|"]
    for name, modes in micro["micro"].items():
        base, wiping = (statistics.median(modes[m]) for m in BUILDS)
        unit, scale = ("µs", 1e3) if base >= 1e3 else ("ns", 1)
        lines.append(f"| {name} | {base / scale:,.1f} {unit} | {wiping / scale:,.1f} {unit} | "
                     f"{cost(base, wiping)} |")
    return lines


def daemon_report(runs: dict) -> list:
    def median(build, metric):
        return statistics.median(metric(r) for r in runs[build])

    storm_ops = lambda r: sum(len(r["operations_ms"][k]) for k in ("fetch", "commit (signed)", "push"))
    rows = [
        ("Storm wall time (s)", lambda r: r["phases_s"]["storm"], "{:.2f}"),
        ("Storm throughput (operations/s)", lambda r: storm_ops(r) / r["phases_s"]["storm"], "{:.1f}"),
        ("Large push and fetches (s)", lambda r: r["phases_s"]["large"], "{:.2f}"),
        ("writd CPU time, its own process (s)", lambda r: r["cpu_s"], "{:.2f}"),
        ("CPU time, every process of the run (s)", lambda r: r["cpu_all_s"], "{:.2f}"),
        ("writd peak memory, storm (MiB)", lambda r: r["peak_rss_kib"]["storm"] / 1024, "{:.1f}"),
        ("writd peak memory, large push and fetches (MiB)",
         lambda r: r["peak_rss_kib"]["large"] / 1024, "{:.1f}"),
    ]
    lines = ["| Measure (median of runs) | System | Wiping | Cost of wiping |",
             "|---|---:|---:|---:|"]
    for label, metric, fmt in rows:
        base, wiping = median("system", metric), median("wiping", metric)
        shown = cost(base, wiping, higher_is_better="throughput" in label)
        lines.append(f"| {label} | {fmt.format(base)} | {fmt.format(wiping)} | {shown} |")
    lines += ["", "| Operation (ms, every run's samples) | Samples | System p50 | Wiping p50 | "
              "System p99 | Wiping p99 |", "|---|---:|---:|---:|---:|---:|"]
    kinds = sorted({k for build in BUILDS for r in runs[build] for k in r["operations_ms"]})
    for kind in kinds:
        pooled = {b: [x for r in runs[b] for x in r["operations_ms"].get(kind, [])] for b in BUILDS}
        cells = [f"{percentile(pooled[b], p):,.0f}" for p in (50, 99) for b in BUILDS]
        lines.append(f"| {kind} | {len(pooled['wiping'])} | " + " | ".join(cells) + " |")
    return lines


def linux(args: argparse.Namespace) -> None:
    """This script, in a Linux container: what the daemon's own tools need, the tree mounted
    read-write (target/ shadowed by a volume, so no Linux build lands in the host's)."""
    dockerfile = (ROOT / "e2e" / "Dockerfile").read_text()
    image = next(line.split("=", 1)[1] for line in dockerfile.splitlines()
                 if line.startswith("ARG RUST_IMAGE="))
    results = BENCH / "results-linux"
    results.mkdir(parents=True, exist_ok=True)
    inner = ["python3", "-I", "tool/bench-alloc.py", "--runs", str(args.runs),
             "--results", "/results"]
    inner += ["--skip-micro"] if args.skip_micro else []
    inner += ["--skip-daemon"] if args.skip_daemon else []
    setup = ("apt-get update -qq && apt-get install -y -qq --no-install-recommends git "
             "openssh-client netcat-openbsd python3 >/dev/null && ")
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{ROOT}:/src", "-v", "writ-bench-target:/src/target",
         "-v", "writ-bench-cargo:/usr/local/cargo/registry", "-v", f"{results}:/results",
         "-w", "/src", "-e", "RUSTUP_TOOLCHAIN=1.99.1", "-e", "CARGO_TERM_COLOR=never",
         image, "sh", "-c", setup + " ".join(inner)],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--skip-micro", action="store_true")
    parser.add_argument("--skip-daemon", action="store_true")
    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--results", type=pathlib.Path, default=BENCH / "results")
    args = parser.parse_args()
    if args.linux:
        linux(args)
        return

    executable = build()
    results = args.results / time.strftime("%Y%m%d-%H%M%S")
    results.mkdir(parents=True)
    machine = f"{platform.system()} {platform.machine()}, {os.cpu_count()} CPUs"
    report = [f"Machine: {machine}", ""]
    if not args.skip_micro:
        print("bench-alloc: the in-process paths", file=sys.stderr)
        micro = run(executable, "allocation_heavy_paths", results / "micro.json")
        report += micro_report(micro) + [""]
    if not args.skip_daemon:
        runs = {b: [] for b in BUILDS}
        for n in range(args.runs):
            for build_name in (BUILDS if n % 2 == 0 else tuple(reversed(BUILDS))):
                print(f"bench-alloc: writd under load, run {n + 1}/{args.runs}, {build_name}",
                      file=sys.stderr)
                out = results / f"daemon-{build_name}-{n + 1}.json"
                runs[build_name].append(run(executable, "writd_under_heavy_load", out, build_name))
        report += [f"writd under heavy load: {args.runs} runs per build", ""]
        report += daemon_report(runs)
    text = "\n".join(report) + "\n"
    (results / "report.md").write_text(text)
    print(text)
    print(f"bench-alloc: every run's numbers in {results}", file=sys.stderr)


if __name__ == "__main__":
    main()
