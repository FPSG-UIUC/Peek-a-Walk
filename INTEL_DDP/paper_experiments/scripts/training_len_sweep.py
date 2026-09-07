#!/usr/bin/env python3
"""
Sweep training_len_flush.out over training_size for both flush states and plot
the chosen metric vs training_size as two series (flush off vs flush on).

training_len_flush.out usage:  ./training_len_flush.out <training size> <flush_enable>
test_ptr_offset is hardcoded to 16 inside the binary. It trains on training_aop
(deref on), does one activation on test_aop[0] (deref off), with the target
planted at test_aop[16]; base/attack alternates NULL vs ptr. When flush_enable=1
the whole training aop is clflushed every iteration; when 0 it stays resident.
So this isolates: does flushing the training data change DMP activation as a
function of training length? It prints TRIALS access times to stderr, then an
"Average:" line (skipped by the parser).

Running this:
  1. Sweeps (training_size x flush in {0,1}), pooling sub-CLIP times across RUNS,
     and writes ./training_len_flush_sweep/summary.csv
     (cols: training_size, flush, mean, median, hit_rate, n). Overwrites.
  2. Draws one line plot: x = training_size, y = chosen metric, one line per
     flush state. mean/median: lower = faster = DMP activated. hit_rate: higher.

Usage:
    ./training_len_flush.py                 # sweep (overwrites) then plot mean
    ./training_len_flush.py median          # sweep then plot median
    ./training_len_flush.py hit_rate        # sweep then plot hit_rate
Set PLOT_ONLY=True below to skip the sweep and just re-plot from summary.csv
(metric still comes from the arg above).
"""
import os, sys, csv, subprocess, statistics
import numpy as np
import matplotlib
matplotlib.use("Agg")              # headless / over SSH
import matplotlib.pyplot as plt

# ------------------------------------------------------------------ EDIT ME
BINARY         = "../training_len_flush.out"   # may be "../training_len_flush.out"
SWEEP_DIR      = "./training_len_flush_sweep"
TRAINING_SIZES = list(range(15,25, 1))   # arg 1 -> x axis
FLUSH_STATES   = [0, 1]                    # arg 2 -> one line each
HIT_THRESH     = 50                    # cycles; access time < this = hit
CLIP           = 1000                   # drop timer-noise outliers
RUNS           = 1                      # repeats per combo (pooled)
PLOT_ONLY      = False                  # True = skip the sweep, just re-plot from existing summary.csv
# -------------------------------------------------------------------------

CSV_PATH = os.path.join(SWEEP_DIR, "summary.csv")


# --- sweep -------------------------------------------------------------------
def latencies(training_size, flush):
    r = subprocess.run([BINARY, str(training_size), str(flush)],
                       capture_output=True, text=True)
    blob = (r.stdout or "") + "\n" + (r.stderr or "")
    for line in blob.splitlines():
        toks = line.split()
        if len(toks) > 100 and all(t.lstrip('-').isdigit() for t in toks):
            return [int(t) for t in toks]
    return []


def run_sweep():
    if not os.path.exists(BINARY):
        raise SystemExit(f"{BINARY} not found. Build/rename it or fix BINARY "
                         f"(binaries often live one dir up).")
    os.makedirs(SWEEP_DIR, exist_ok=True)
    total = len(TRAINING_SIZES) * len(FLUSH_STATES)
    print(f"sweeping {total} combos x {RUNS} runs -> {CSV_PATH}")
    with open(CSV_PATH, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["training_size", "flush", "mean", "median", "hit_rate", "n"])
        done = 0
        for f in FLUSH_STATES:
            for t in TRAINING_SIZES:
                pool = []
                for _ in range(RUNS):
                    pool += [x for x in latencies(t, f) if x < CLIP]
                if pool:
                    row = [t, f, statistics.fmean(pool), statistics.median(pool),
                           sum(x < HIT_THRESH for x in pool) / len(pool), len(pool)]
                else:
                    row = [t, f, "", "", "", 0]
                w.writerow(row)
                done += 1
            print(f"  flush={f}  ({done}/{total})")
    print(f"wrote {CSV_PATH}")


# --- visualize ---------------------------------------------------------------
def visualize(metric):
    if not os.path.exists(CSV_PATH):
        raise SystemExit(f"{CSV_PATH} not found; run once with PLOT_ONLY=False first.")

    rows = []
    with open(CSV_PATH) as fh:
        rd = csv.DictReader(fh)
        if metric not in rd.fieldnames:
            raise SystemExit(f"'{metric}' not in summary.csv; pick one of: {rd.fieldnames}")
        for row in rd:
            if row["mean"]:
                rows.append(row)
    if not rows:
        raise SystemExit("no usable rows in summary.csv")

    higher_better = metric == "hit_rate"
    ylabel = "hit rate" if higher_better else f"{metric} access time (cyc)"

    fig, ax = plt.subplots(figsize=(12, 6))
    colors = {0: "tab:blue", 1: "tab:orange"}
    for f in sorted({int(r["flush"]) for r in rows}):
        pts = sorted(((int(r["training_size"]), float(r[metric]))
                      for r in rows if int(r["flush"]) == f), key=lambda x: x[0])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, lw=1.2, marker="o", ms=3,
                color=colors.get(f), label=f"flush {'on' if f else 'off'} ({f})")

    if higher_better:
        ax.set_ylim(-0.02, 1.05)
    ax.set_xlabel("training_size")
    ax.set_ylabel(ylabel)
    ax.set_title(f"training_len_flush sweep: {metric}  (test_ptr_offset=16)")
    ax.grid(True, lw=0.3)
    ax.legend(loc="best", fontsize=9)
    fig.tight_layout()

    out = f"training_len_flush_{metric}.png"
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")


def main():
    metric = sys.argv[1] if len(sys.argv) > 1 else "mean"
    if PLOT_ONLY:
        if not os.path.exists(CSV_PATH):
            raise SystemExit(f"PLOT_ONLY=True but {CSV_PATH} doesn't exist; set PLOT_ONLY=False and run once first.")
    else:
        run_sweep()   # re-runs the experiments, overwriting summary.csv
    visualize(metric)


if __name__ == "__main__":
    main()