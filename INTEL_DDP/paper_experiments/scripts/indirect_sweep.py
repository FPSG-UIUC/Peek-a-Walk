#!/usr/bin/env python3
"""
Sweep indirect.out over (training_size, test_ptr_offset) and visualize as a
heatmap, in one file.

indirect.out usage:  ./indirect.out <training size> <test ptr offset>
It prints (stderr) ~10000 atck latencies on one line (an "Average:" line, if
present, is skipped). indirect.c tests base+index addressing: training_idx
holds indices into training_buffer, the consumer load is buf[index], and the
target index is planted one past the walked window -- a hit means the DMP ran
ahead and speculatively computed buf[index] through the indexed form.

Running this:
  1. Sweeps (training_size, test_ptr_offset), pooling sub-CLIP latencies across
     RUNS, and writes ./indirect_sweep/summary.csv
     (cols: training_size, test_ptr, mean, median, hit_rate, n). Overwrites.
  2. Draws one heatmap: rows = test_ptr, cols = training_size, colour = chosen
     metric. mean/median: lower (darker) = faster = DMP reached that cell.
     hit_rate: higher = more hits.

Usage:
    ./indirect.py                 # sweep (overwrites) then plot mean
    ./indirect.py median          # sweep then plot median
    ./indirect.py hit_rate        # sweep then plot hit_rate
Set PLOT_ONLY=True below to skip the sweep and just re-plot from the existing
summary.csv (metric still comes from the arg above).
"""
import os, sys, csv, subprocess, statistics
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")              # headless / over SSH
import matplotlib.pyplot as plt

# ------------------------------------------------------------------ EDIT ME
BINARY         = "./indirect.out"      # may be "../indirect.out"
SWEEP_DIR      = "./indirect_sweep"
TRAINING_SIZES = list(range(0, 513, 8))   # arg 1 -> heatmap x
TEST_PTRS      = list(range(0, 132))      # arg 2 -> heatmap y
HIT_THRESH     = 100                    # cycles; latency < this = hit
CLIP           = 1000                   # drop latencies >= CLIP as noise
RUNS           = 2                      # repeats per combo (pooled)
PLOT_ONLY      = False                  # True = skip the sweep, just re-plot from existing summary.csv
# -------------------------------------------------------------------------

CSV_PATH = os.path.join(SWEEP_DIR, "summary.csv")


# --- sweep -------------------------------------------------------------------
def latencies(training_size, test_ptr):
    r = subprocess.run([BINARY, str(training_size), str(test_ptr)],
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
    total = len(TRAINING_SIZES) * len(TEST_PTRS)
    print(f"sweeping {total} combos x {RUNS} runs -> {CSV_PATH}")
    with open(CSV_PATH, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["training_size", "test_ptr", "mean", "median", "hit_rate", "n"])
        done = 0
        for t in TRAINING_SIZES:
            for p in TEST_PTRS:
                pool = []
                for _ in range(RUNS):
                    pool += [x for x in latencies(t, p) if x < CLIP]
                if pool:
                    row = [t, p, statistics.fmean(pool), statistics.median(pool),
                           sum(x < HIT_THRESH for x in pool) / len(pool), len(pool)]
                else:
                    row = [t, p, "", "", "", 0]
                w.writerow(row)
                done += 1
            print(f"  training_size={t:>4}  ({done}/{total})")
    print(f"wrote {CSV_PATH}")


# --- visualize ---------------------------------------------------------------
def visualize(metric):
    df = pd.read_csv(CSV_PATH)
    if metric not in df.columns:
        raise SystemExit(f"'{metric}' not in summary.csv; pick one of: {list(df.columns)}")
    df[metric] = pd.to_numeric(df[metric], errors="coerce")   # blanks -> NaN, guard dtype

    grid = df.pivot(index="test_ptr", columns="training_size", values=metric)

    higher_better = metric == "hit_rate"
    cmap = "viridis" if higher_better else "viridis_r"
    direction = "higher = more hits" if higher_better else "lower = faster"

    fig, ax = plt.subplots(figsize=(12, 7))
    im = ax.imshow(grid.values, aspect="auto", cmap=cmap, origin="lower",
                   interpolation="nearest")
    fig.colorbar(im, ax=ax, label=f"{metric}  ({direction})")

    cols, rows = list(grid.columns), list(grid.index)
    xstep = max(1, len(cols) // 15)
    ystep = max(1, len(rows) // 15)
    ax.set_xticks(range(0, len(cols), xstep))
    ax.set_xticklabels(cols[::xstep], rotation=90, fontsize=8)
    ax.set_yticks(range(0, len(rows), ystep))
    ax.set_yticklabels(rows[::ystep], fontsize=8)

    ax.set_xticks(np.arange(-0.5, len(cols), xstep), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), ystep), minor=True)
    ax.grid(which="minor", color="white", linewidth=0.4, alpha=0.5)
    ax.tick_params(which="minor", length=0)

    ax.set_xlabel("training_size")
    ax.set_ylabel("test_ptr (OOB offset)")
    ax.set_title(f"indirect sweep: {metric}")
    fig.tight_layout()

    out = f"indirect_{metric}.png"
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