import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_CACHE_DIR = os.path.join(BASE_DIR, ".matplotlib-cache")
os.environ.setdefault("MPLCONFIGDIR", LOCAL_CACHE_DIR)
os.environ.setdefault("XDG_CACHE_HOME", LOCAL_CACHE_DIR)

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams
import numpy as np


rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Helvetica", "Arial", "Liberation Sans", "DejaVu Sans"],
    "mathtext.fontset": "stix",
    "font.size": 12,
    "pdf.use14corefonts": True,
    "ps.useafm": True,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    # The 14 core PDF fonts have no glyph for the Unicode minus (U+2212)
    # that matplotlib uses by default, which renders as a missing-glyph
    # box/"?" -- force the plain ASCII hyphen instead.
    "axes.unicode_minus": False,
})


BAR_STYLE = {
    "SYGMA": {"facecolor": "black", "edgecolor": "black", "linestyle": "-"},
    "Tetragon": {"facecolor": "white", "edgecolor": "black", "linestyle": "--"},
}

# Fixed across both figures so the two plots share one aspect ratio
# regardless of how many containers each one lists.
FIGSIZE = (14.0, 7.2)


def _strip_app_prefix(name):
    for prefix in ("hotel-", "boutique-"):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def save_diverging_timing_pdf(
    rows,
    sygma_key,
    tetragon_key,
    tetragon_missed_key,
    tetragon_missed_max,
    save_name="figure.pdf",
    y_label="Policy Activation (ms)",
    y2_label="Missed syscalls",
    figsize=FIGSIZE,
    bar_width=0.58,
    font_size=14,
    tick_font_size=13,
    label_font_size=12,
    spine_width=1.1,
    legend_loc="upper center",
    legend_bbox=(0.5, 1.17),
    legend_ncol=2,
    label_rotation=40,
    value_fmt="{:.1f}",
    missed_value_fmt="{:.0f}",
):
    """Grouped bar chart, one pair per container: Tetragon on the left
    (bar extends upward -- policy only lands after the syscall already
    ran), SYGMA on the right (bar extends downward -- policy is already
    applied before the syscall fires). Value labels show plain magnitudes
    (ms) above the Tetragon bar and below the SYGMA bar. Container names
    run along the x-axis with the hotel-/boutique- prefix stripped.

    A second line series (Tetragon's missed application syscalls,
    right-hand axis) is overlaid above the bars. Within each figure, the
    left bar axis and right line axis both use tetragon_missed_max as
    their numeric Y maximum.
    SYGMA's missed-syscall count is 0 everywhere and is omitted."""

    labels = [_strip_app_prefix(r["name"]) for r in rows]
    n = len(labels)
    x = np.arange(n)
    half = bar_width / 2.0

    sygma_raw = np.array([r[sygma_key] for r in rows], dtype=float)
    tetragon_raw = np.array([r[tetragon_key] for r in rows], dtype=float)

    # Tetragon bars extend upward, SYGMA bars extend downward.
    sygma_bar = -np.abs(sygma_raw)
    tetragon_bar = np.abs(tetragon_raw)

    if not any(save_name.endswith(ext) for ext in (".pdf", ".png", ".svg")):
        save_name = f"{save_name}.pdf"
    if not os.path.isabs(save_name):
        save_name = os.path.join(BASE_DIR, save_name)

    fig, ax = plt.subplots(figsize=figsize)

    s = BAR_STYLE["SYGMA"]
    t = BAR_STYLE["Tetragon"]

    ax.bar(x - half / 2, tetragon_bar, width=half, facecolor=t["facecolor"],
           edgecolor=t["edgecolor"], linestyle=t["linestyle"], linewidth=1.3,
           zorder=2, label="Tetragon")
    ax.bar(x + half / 2, sygma_bar, width=half, facecolor=s["facecolor"],
           edgecolor=s["edgecolor"], linestyle=s["linestyle"], linewidth=1.3,
           zorder=2, label="SYGMA")

    ax.axhline(0, color="black", linewidth=1.0, zorder=1)

    for xi, tv in zip(x, tetragon_bar):
        ax.annotate(value_fmt.format(tv), xy=(xi - half / 2, tv), xycoords="data",
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=label_font_size)

    for xi, sv in zip(x, sygma_bar):
        ax.annotate(value_fmt.format(abs(sv)), xy=(xi + half / 2, sv), xycoords="data",
                    xytext=(0, -3), textcoords="offset points",
                    ha="center", va="top", fontsize=label_font_size)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=tick_font_size, rotation=label_rotation,
                        ha="right", rotation_mode="anchor")
    ax.set_xlim(-0.7, n - 0.3)

    # Both y-axes use the same numeric upper bound within this figure.
    # The bottom (SYGMA side) keeps generous padding so the tiny SYGMA
    # bars and their labels stay clear of the x-axis tick labels.
    top_pad = 1.12
    bottom_pad_frac = 0.32

    tetragon_missed_raw = np.array([r[tetragon_missed_key] for r in rows], dtype=float)
    tetragon_missed = np.abs(tetragon_missed_raw)

    y_min = min(sygma_bar.min(), 0)
    # Both axes use tetragon_missed_max and the same top padding.
    y_max_raw = tetragon_missed_max
    y_max = y_max_raw * top_pad
    y_min_padded = y_min - (y_max_raw - y_min) * bottom_pad_frac
    ax.set_ylim(y_min_padded, y_max)
    ax.set_ylabel(y_label, fontsize=font_size)

    ax.grid(False)

    handles, legend_labels = ax.get_legend_handles_labels()

    ax2 = ax.twinx()

    # Align the twin axis' zero line with the primary axis' zero line while
    # retaining the same shared upper bound on both axes.
    frac = (0 - y_min_padded) / (y_max - y_min_padded)
    y2_max = y_max
    y2_min = -frac * y2_max / (1 - frac)
    ax2.set_ylim(y2_min, y2_max)

    (line_t,) = ax2.plot(x, tetragon_missed, color=t["edgecolor"],
                          linestyle=t["linestyle"], linewidth=1.4, marker="o",
                          markerfacecolor=t["facecolor"], markeredgecolor="black",
                          markersize=6, zorder=5, label="Tetragon missed syscalls")

    for xi, tv, traw in zip(x, tetragon_missed, tetragon_missed_raw):
        ax2.annotate(missed_value_fmt.format(traw), xy=(xi, tv), xycoords="data",
                     xytext=(0, 10), textcoords="offset points",
                     ha="center", va="bottom", fontsize=label_font_size,
                     fontstyle="italic")

    ax2.set_ylabel(y2_label, fontsize=font_size)
    ax2.tick_params(axis="y", which="major", direction="in", length=4, width=1.0,
                     labelsize=font_size - 1)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_linewidth(spine_width)

    handles += [line_t]
    legend_labels += ["Tetragon (missed syscalls)"]

    ax.legend(handles, legend_labels, loc=legend_loc, bbox_to_anchor=legend_bbox,
              ncol=legend_ncol, frameon=True, fancybox=False, framealpha=0.0,
              fontsize=font_size - 2, handletextpad=0.6, columnspacing=1.4)

    ax.tick_params(axis="x", which="both", length=0, pad=4)
    ax.tick_params(axis="y", which="major", direction="in", length=4, width=1.0,
                    labelsize=font_size - 1)
    ax.spines["top"].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_linewidth(spine_width)

    plt.tight_layout()
    plt.savefig(save_name, dpi=200, bbox_inches="tight")
    plt.close()
    return save_name


HOTEL_ROWS = [
    {"name": "hotel-frontend", "sygma_ready_to_first_ms": 22.88, "tetragon_ready_to_first_ms": -124.59, "sygma_missed": 0, "tetragon_missed": 1907.0},
    {"name": "hotel-geo", "sygma_ready_to_first_ms": 22.75, "tetragon_ready_to_first_ms": -100.02, "sygma_missed": 0, "tetragon_missed": 1313.5},
    {"name": "hotel-profile", "sygma_ready_to_first_ms": 27.30, "tetragon_ready_to_first_ms": -61.68, "sygma_missed": 0, "tetragon_missed": 869.5},
    {"name": "hotel-rate", "sygma_ready_to_first_ms": 23.85, "tetragon_ready_to_first_ms": -920.31, "sygma_missed": 0, "tetragon_missed": 1136.0},
    {"name": "hotel-recommendation", "sygma_ready_to_first_ms": 27.00, "tetragon_ready_to_first_ms": -93.81, "sygma_missed": 0, "tetragon_missed": 1172.0},
    {"name": "hotel-reservation", "sygma_ready_to_first_ms": 24.25, "tetragon_ready_to_first_ms": -116.91, "sygma_missed": 0, "tetragon_missed": 1128.5},
    {"name": "hotel-search", "sygma_ready_to_first_ms": 22.59, "tetragon_ready_to_first_ms": -324.23, "sygma_missed": 0, "tetragon_missed": 1760.0},
    {"name": "hotel-user", "sygma_ready_to_first_ms": 22.77, "tetragon_ready_to_first_ms": -321.77, "sygma_missed": 0, "tetragon_missed": 1947.5},
    {"name": "hotel-consul", "sygma_ready_to_first_ms": 22.37, "tetragon_ready_to_first_ms": -921.70, "sygma_missed": 0, "tetragon_missed": 3660.5},
    {"name": "hotel-jaeger", "sygma_ready_to_first_ms": 23.69, "tetragon_ready_to_first_ms": -308.89, "sygma_missed": 0, "tetragon_missed": 1487.0},
    {"name": "hotel-mongo-geo", "sygma_ready_to_first_ms": 27.28, "tetragon_ready_to_first_ms": -176.34, "sygma_missed": 0, "tetragon_missed": 2420.5},
    {"name": "hotel-mongo-profile", "sygma_ready_to_first_ms": 27.08, "tetragon_ready_to_first_ms": -110.13, "sygma_missed": 0, "tetragon_missed": 2418.5},
    {"name": "hotel-mongo-rate", "sygma_ready_to_first_ms": 23.99, "tetragon_ready_to_first_ms": -104.46, "sygma_missed": 0, "tetragon_missed": 2417.5},
    {"name": "hotel-mongo-recommendation", "sygma_ready_to_first_ms": 22.31, "tetragon_ready_to_first_ms": -174.99, "sygma_missed": 0, "tetragon_missed": 2416.0},
    {"name": "hotel-mongo-reservation", "sygma_ready_to_first_ms": 22.50, "tetragon_ready_to_first_ms": -179.56, "sygma_missed": 0, "tetragon_missed": 2421.0},
    {"name": "hotel-mongo-user", "sygma_ready_to_first_ms": 22.40, "tetragon_ready_to_first_ms": -128.24, "sygma_missed": 0, "tetragon_missed": 2418.5},
    {"name": "hotel-memcached-profile", "sygma_ready_to_first_ms": 22.17, "tetragon_ready_to_first_ms": -261.43, "sygma_missed": 0, "tetragon_missed": 497.0},
    {"name": "hotel-memcached-rate", "sygma_ready_to_first_ms": 20.98, "tetragon_ready_to_first_ms": -314.15, "sygma_missed": 0, "tetragon_missed": 499.0},
    {"name": "hotel-memcached-reserve", "sygma_ready_to_first_ms": 21.45, "tetragon_ready_to_first_ms": -276.83, "sygma_missed": 0, "tetragon_missed": 495.5},
]

BOUTIQUE_ROWS = [
    {"name": "boutique-ad", "sygma_ready_to_first_ms": 26.15, "tetragon_ready_to_first_ms": -831.77, "sygma_missed": 0, "tetragon_missed": 44148.5},
    {"name": "boutique-cart", "sygma_ready_to_first_ms": 23.29, "tetragon_ready_to_first_ms": -623.66, "sygma_missed": 0, "tetragon_missed": 7850.0},
    {"name": "boutique-checkout", "sygma_ready_to_first_ms": 24.27, "tetragon_ready_to_first_ms": -206.92, "sygma_missed": 0, "tetragon_missed": 1016.0},
    {"name": "boutique-currency", "sygma_ready_to_first_ms": 25.19, "tetragon_ready_to_first_ms": -245.34, "sygma_missed": 0, "tetragon_missed": 12880.0},
    {"name": "boutique-email", "sygma_ready_to_first_ms": 25.38, "tetragon_ready_to_first_ms": -143.44, "sygma_missed": 0, "tetragon_missed": 5365.0},
    {"name": "boutique-frontend", "sygma_ready_to_first_ms": 25.22, "tetragon_ready_to_first_ms": -135.11, "sygma_missed": 0, "tetragon_missed": 1517.0},
    {"name": "boutique-payment", "sygma_ready_to_first_ms": 24.17, "tetragon_ready_to_first_ms": -233.03, "sygma_missed": 0, "tetragon_missed": 12055.0},
    {"name": "boutique-productcatalog", "sygma_ready_to_first_ms": 23.11, "tetragon_ready_to_first_ms": -163.60, "sygma_missed": 0, "tetragon_missed": 734.0},
    {"name": "boutique-recommendation", "sygma_ready_to_first_ms": 25.74, "tetragon_ready_to_first_ms": -168.19, "sygma_missed": 0, "tetragon_missed": 5686.0},
    {"name": "boutique-shipping", "sygma_ready_to_first_ms": 26.53, "tetragon_ready_to_first_ms": -121.16, "sygma_missed": 0, "tetragon_missed": 531.5},
    {"name": "boutique-redis-cart", "sygma_ready_to_first_ms": 26.60, "tetragon_ready_to_first_ms": -97.71, "sygma_missed": 0, "tetragon_missed": 2110.0},
]


if __name__ == "__main__":
    HOTEL_TETRAGON_MISSED_MAX = max(
        abs(r["tetragon_missed"]) for r in HOTEL_ROWS
    )
    BOUTIQUE_TETRAGON_MISSED_MAX = max(
        abs(r["tetragon_missed"]) for r in BOUTIQUE_ROWS
    )

    out1 = save_diverging_timing_pdf(
        HOTEL_ROWS,
        sygma_key="sygma_ready_to_first_ms",
        tetragon_key="tetragon_ready_to_first_ms",
        tetragon_missed_key="tetragon_missed",
        tetragon_missed_max=HOTEL_TETRAGON_MISSED_MAX,
        save_name="fig-eval-q3-policy-timing-hotel.pdf",
    )
    print("saved:", out1)

    out2 = save_diverging_timing_pdf(
        BOUTIQUE_ROWS,
        sygma_key="sygma_ready_to_first_ms",
        tetragon_key="tetragon_ready_to_first_ms",
        tetragon_missed_key="tetragon_missed",
        tetragon_missed_max=BOUTIQUE_TETRAGON_MISSED_MAX,
        save_name="fig-eval-q3-policy-timing-boutique.pdf",
    )
    print("saved:", out2)
