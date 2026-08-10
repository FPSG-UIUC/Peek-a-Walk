#!/usr/bin/env python3
"""
Sweep prefetch_distance.out and visualize the result as a heatmap, in one file.

prefetch_distance.out usage:  ./prefetch_distance.out <access_size> <test_ptr> <stride>
It prints (stderr) ~10000 atck latencies on one line (an "Average:" line, if
present, is skipped).

Running this:
  1. If ./prefetch_distance_sweep/summary.csv is missing (or RESWEEP=True), it
     sweeps (stride, access_size, test_ptr), pooling sub-CLIP latencies across
     RUNS, and writes summary.csv (cols: stride, access_size, test_ptr, mean,
     median, hit_rate, n).
  2. It then draws one heatmap: rows = test_ptr, cols = access_size, colour =
     chosen metric for the chosen stride. mean/median: lower (darker) = faster
     = DMP reached that cell. hit_rate: higher = more hits.

Usage:
    ./prefetch_distance.py                 # mean, first stride in csv
    ./prefetch_distance.py median          # median
    ./prefetch_distance.py hit_rate 2      # hit_rate at stride=2
Set RESWEEP=True (or delete summary.csv) to force a fresh sweep.
"""
import os, sys, csv, subprocess, statistics, math
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")              # headless / over SSH
import matplotlib.pyplot as plt

# ------------------------------------------------------------------ EDIT ME
BINARY       = "../prefetch_distance.out"   # may be "../prefetch_distance.out"
SWEEP_DIR    = "./prefetch_distance_sweep"
ACCESS_SIZES = list(range(0, 50))     # arg 1
TEST_PTRS    = list(range(0, 100))     # arg 2
STRIDES      = [1,2,3]                     # arg 3
HIT_THRESH   = 50                     # cycles; latency < this = hit
CLIP         = 1000                    # drop latencies >= CLIP as noise
RUNS         = 1                       # repeats per combo (pooled)
RESWEEP      = True                   # True forces re-running the sweep
# -------------------------------------------------------------------------

CSV_PATH = os.path.join(SWEEP_DIR, "summary.csv")


# --- sweep -------------------------------------------------------------------
def latencies(access_size, test_ptr, stride):
    r = subprocess.run([BINARY, str(access_size), str(test_ptr), str(stride)],
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
    total = len(STRIDES) * len(ACCESS_SIZES) * len(TEST_PTRS)
    print(f"sweeping {total} combos x {RUNS} runs -> {CSV_PATH}")
    with open(CSV_PATH, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["stride", "access_size", "test_ptr", "mean", "median", "hit_rate", "n"])
        done = 0
        for s in STRIDES:
            for a in ACCESS_SIZES:
                for p in TEST_PTRS:
                    pool = []
                    for _ in range(RUNS):
                        pool += [x for x in latencies(a, p, s) if x < CLIP]
                    if pool:
                        row = [s, a, p, statistics.fmean(pool), statistics.median(pool),
                               sum(x < HIT_THRESH for x in pool) / len(pool), len(pool)]
                    else:
                        row = [s, a, p, "", "", "", 0]
                    w.writerow(row)
                    done += 1
                print(f"  stride={s} access={a:>3}  ({done}/{total})")
    print(f"wrote {CSV_PATH}")


# --- visualize ---------------------------------------------------------------
def visualize(metric, stride_arg):
    df = pd.read_csv(CSV_PATH)
    if metric not in df.columns:
        raise SystemExit(f"'{metric}' not in summary.csv; pick one of: {list(df.columns)}")
    df[metric] = pd.to_numeric(df[metric], errors="coerce")   # blanks -> NaN, guard dtype

    all_strides = sorted(df["stride"].unique())
    if stride_arg is not None:
        stride = int(stride_arg)
        if stride not in all_strides:
            raise SystemExit(f"stride {stride} not in csv; available: {all_strides}")
        strides = [stride]
    else:
        strides = all_strides   # show every stride we swept

    higher_better = metric == "hit_rate"
    cmap = "viridis" if higher_better else "viridis_r"
    direction = "higher = more hits" if higher_better else "lower = faster"

    # one grid per stride; shared color scale so panels are comparable
    grids = {s: df[df["stride"] == s].pivot(index="test_ptr", columns="access_size",
                                            values=metric) for s in strides}
    allvals = np.concatenate([g.values.astype(float).ravel() for g in grids.values()])
    finite = allvals[np.isfinite(allvals)]
    vmin, vmax = (float(finite.min()), float(finite.max())) if finite.size else (0.0, 1.0)

    n = len(strides)
    ncols = min(3, n)
    nrows = math.ceil(n / ncols)
    fig, axes = plt.subplots(nrows, ncols, figsize=(6 * ncols, 6 * nrows), squeeze=False)
    axes = axes.ravel()

    im = None
    for i, s in enumerate(strides):
        ax = axes[i]
        g = grids[s]
        im = ax.imshow(g.values, aspect="auto", cmap=cmap, origin="lower",
                       interpolation="nearest", vmin=vmin, vmax=vmax)
        cols, rows = list(g.columns), list(g.index)
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
        ax.set_xlabel("access_size (# triggers)")
        ax.set_ylabel("test_ptr (secret offset)")
        ax.set_title(f"stride = {s}")
    for j in range(n, len(axes)):
        axes[j].axis("off")

    fig.colorbar(im, ax=axes[:n].tolist(), label=f"{metric}  ({direction})", shrink=0.6)
    fig.suptitle(f"prefetch_distance sweep: {metric}", fontsize=13)

    tag = f"s{strides[0]}" if stride_arg is not None else "all"
    out = f"prefetch_distance_{metric}_{tag}.png"
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")


def main():
    metric = sys.argv[1] if len(sys.argv) > 1 else "mean"
    stride_arg = sys.argv[2] if len(sys.argv) > 2 else None
    run_sweep()   # always re-runs the experiments, overwriting summary.csv
    visualize(metric, stride_arg)


if __name__ == "__main__":
    main()