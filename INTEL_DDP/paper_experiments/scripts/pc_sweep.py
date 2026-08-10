#!/usr/bin/env python3
"""
Sweep pc.out over the trigger-load PC offset and visualize mean/median access
time (+ hit rate) vs PC offset, in one file.

pc.out usage:  ./pc.out <pc_train_rel> <pc_test_offset>
The train load is fixed at DEFAULT_BASE (pc_train_rel=0); we sweep pc_test_offset
across one 0x400 (1024) PC-index period above pc.c's assert floor (>4120).
pc.out writes its TRIALS access times to stderr. Low times / high hit rate =
the DMP prefetched ptr_under_test (PC aliasing activated it).

pc.out asserts internally and aborts (SIGABRT -> nonzero return) on some offsets;
those are skipped, any stale row dropped, and the first few assert messages are
printed so you can see which check tripped.

Running this:
  1. Sweeps pc_test_offset, pooling sub-CLIP times across RUNS, and writes
     ./pc_sweep/summary.csv (cols: offset, mean, median, hit_rate, n). Overwrites.
  2. Draws one line plot: x = PC offset (hex), left y = chosen metric (mean or
     median access time), right y = hit rate. The activation peak (lowest mean)
     is marked. For hit_rate as the metric, the left axis shows hit rate instead.

Usage:
    ./pc.py                 # sweep (overwrites) then plot mean
    ./pc.py median          # sweep then plot median
    ./pc.py hit_rate        # sweep then plot hit_rate
Set PLOT_ONLY=True below to skip the sweep and just re-plot from summary.csv
(metric still comes from the arg above).
"""
import os, sys, csv, subprocess, statistics
import numpy as np
import matplotlib
matplotlib.use("Agg")              # headless / over SSH
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# ------------------------------------------------------------------ EDIT ME
BINARY       = "./pc.out"              # may be "../pc.out"
SWEEP_DIR    = "./pc_sweep"
PC_TRAIN_REL = 0                       # arg 1: train load fixed at DEFAULT_BASE
START        = 4121                    # arg 2 start (pc.c asserts pc_test_offset > 4120)
END          = 5145                    # exclusive; START + 1024 = one PC-index period (PC_MASK=0x3ff)
BASE_ADDR    = 0x666600000000          # PC = BASE_ADDR + offset (for the axis label)
HIT_THRESH   = 50                      # cycles; access time < this = hit / DMP activation
CLIP         = 1000                    # drop timer-noise outliers
RUNS         = 2                       # repeats per offset (pooled)
PLOT_ONLY    = True                   # True = skip the sweep, just re-plot from existing summary.csv
# -------------------------------------------------------------------------

CSV_PATH = os.path.join(SWEEP_DIR, "summary.csv")


# --- sweep -------------------------------------------------------------------
def times_for(offset):
    """Run pc.out once for one offset. Returns (times, err): times=[] if aborted."""
    r = subprocess.run([BINARY, str(PC_TRAIN_REL), str(offset)],
                       capture_output=True, text=True)
    if r.returncode != 0:                        # SIGABRT -> negative/nonzero
        return [], r.stderr.strip()
    for line in r.stderr.splitlines():           # pc.out writes timings to stderr
        toks = line.split()
        if len(toks) > 100 and all(t.lstrip('-').isdigit() for t in toks):
            return [int(t) for t in toks], ""
    return [], "no data line"


def run_sweep():
    if not os.path.exists(BINARY):
        raise SystemExit(f"{BINARY} not found. Build/rename it or fix BINARY "
                         f"(binaries often live one dir up).")
    os.makedirs(SWEEP_DIR, exist_ok=True)
    total = END - START
    print(f"sweeping offsets {START}..{END - 1} x {RUNS} runs -> {CSV_PATH}")
    fails = 0
    with open(CSV_PATH, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["offset", "mean", "median", "hit_rate", "n"])
        for off in range(START, END):
            pool, aborted = [], False
            for _ in range(RUNS):
                ts, err = times_for(off)
                if not ts:
                    aborted = True
                    if fails < 3:
                        print(f"[off={off}] aborted -- {err}", file=sys.stderr)
                    fails += 1
                    break
                pool += [x for x in ts if x < CLIP]
            if aborted or not pool:
                continue                          # skip: no row for aborted offsets
            w.writerow([off, statistics.fmean(pool), statistics.median(pool),
                        sum(x < HIT_THRESH for x in pool) / len(pool), len(pool)])
    print(f"done: swept {total} offsets, {fails} runs aborted (failed assert inside pc.out)")


# --- visualize ---------------------------------------------------------------
def visualize(metric):
    if not os.path.exists(CSV_PATH):
        raise SystemExit(f"{CSV_PATH} not found; run once with PLOT_ONLY=False first.")

    offs, means, medians, hits = [], [], [], []
    with open(CSV_PATH) as fh:
        rd = csv.DictReader(fh)
        cols = rd.fieldnames
        if metric not in cols:
            raise SystemExit(f"'{metric}' not in summary.csv; pick one of: {cols}")
        for row in rd:
            if not row["mean"]:
                continue
            offs.append(int(row["offset"]))
            means.append(float(row["mean"]))
            medians.append(float(row["median"]))
            hits.append(float(row["hit_rate"]))
    if not offs:
        raise SystemExit("no usable rows in summary.csv")

    order = np.argsort(offs)
    offs    = np.array(offs)[order]
    means   = np.array(means)[order]
    medians = np.array(medians)[order]
    hits    = np.array(hits)[order]

    # activation peak = lowest mean access time
    peak = int(offs[np.argmin(means)])
    print(f"{len(offs)} offsets; activation peak (min mean) @ 0x{peak:X} "
          f"({means.min():.1f} cyc)")

    left = {"mean": means, "median": medians, "hit_rate": hits}[metric]
    left_is_hit = metric == "hit_rate"
    left_label = "hit rate" if left_is_hit else f"{metric} access time (cyc)"

    fig, ax = plt.subplots(figsize=(22, 5))
    ax.plot(offs, left, lw=0.8, color="tab:blue", label=left_label)
    ax.set_ylabel(left_label, color="tab:blue")
    ax.tick_params(axis="y", labelcolor="tab:blue")
    ax.set_xlabel(f"PC test offset   (PC = 0x{BASE_ADDR:X} + offset)")
    ax.axvline(peak, color="red", ls="--", lw=1)
    ax.annotate(f"0x{peak:X}", xy=(peak, np.max(left)), color="red",
                ha="center", va="bottom", fontsize=9)
    if left_is_hit:
        ax.set_ylim(-0.02, 1.05)

    # twin axis: always show hit rate on the right (unless it's already the left metric)
    if not left_is_hit:
        ax2 = ax.twinx()
        ax2.plot(offs, hits, lw=0.8, color="tab:green", label=f"hit rate (< {HIT_THRESH} cyc)")
        ax2.set_ylabel(f"hit rate (< {HIT_THRESH} cyc)", color="tab:green")
        ax2.tick_params(axis="y", labelcolor="tab:green")
        ax2.set_ylim(-0.02, 1.05)
        # combined legend across both axes so blue vs green is unambiguous
        lines = ax.get_lines() + ax2.get_lines()
        ax.legend(lines, [l.get_label() for l in lines], loc="upper right", fontsize=9)
    else:
        ax.legend(loc="upper right", fontsize=9)

    # hex ticks on clean 0x100 boundaries
    lo = (offs.min() // 0x100 + 1) * 0x100
    ax.set_xticks(np.arange(lo, offs.max() + 1, 0x100))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"0x{int(x):X}"))
    ax.set_xlim(offs.min(), offs.max())

    ax.set_title(f"pc sweep: {metric} ({len(offs)} offsets), activation @ 0x{peak:X}")
    fig.tight_layout()

    out = f"pc_{metric}.png"
    fig.savefig(out, dpi=120)
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