import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde

# 실험 결과 루트 디렉터리
SVD_DIR = "lanl_svd_experiment"
OUT_DIR = os.path.join(SVD_DIR, "summary_svd")
os.makedirs(OUT_DIR, exist_ok=True)


def load_metrics(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_computer_curve(path):
    df = pd.read_csv(path, index_col=0)
    if "gmm_score" not in df.columns:
        raise RuntimeError(f"gmm_score column not found in {path}")
    df = df.sort_values("gmm_score", ascending=False)
    return df["gmm_score"].values.astype(float)


def collect_runs(root_dir):
    baseline_metrics = None
    baseline_curve = None
    attack_metrics = []
    attack_curves = []
    attack_tags = []

    for name in sorted(os.listdir(root_dir)):
        run_dir = os.path.join(root_dir, name)
        if not os.path.isdir(run_dir):
            continue
        metrics_path = os.path.join(run_dir, "metrics.json")
        comp_path = os.path.join(run_dir, "computer_scores.csv")
        if not (os.path.exists(metrics_path) and os.path.exists(comp_path)):
            continue

        m = load_metrics(metrics_path)
        curve = load_computer_curve(comp_path)

        if name.lower().startswith("baseline"):
            baseline_metrics = m
            baseline_curve = curve
        elif name.lower().startswith("attack_"):
            attack_metrics.append(m)
            attack_curves.append(curve)
            attack_tags.append(name)

    if baseline_curve is None or not attack_curves:
        raise RuntimeError("baseline 또는 attack 결과를 찾을 수 없음")

    return baseline_metrics, baseline_curve, attack_metrics, attack_curves, attack_tags


def compute_recalls(attack_metrics):
    user_recalls = []
    comp_recalls = []
    for m in attack_metrics:
        tu = m.get("total_reduser", 0)
        tc = m.get("total_redcomp", 0)
        hu = m.get("hit_user@100", 0)
        hc = m.get("hit_comp@100", 0)

        user_recalls.append(hu / tu if tu > 0 else 0.0)
        comp_recalls.append(hc / tc if tc > 0 else 0.0)

    return np.array(user_recalls, dtype=float), np.array(comp_recalls, dtype=float)


def plot_anomaly_curve(baseline_curve, attack_curves, out_path):
    # attack 윈도우들 길이가 다르므로 공통 rank 구간을 맞춘다
    min_len_attack = min(len(c) for c in attack_curves)
    n = min(len(baseline_curve), min_len_attack)
    base = baseline_curve[:n]
    atk_mat = np.vstack([c[:n] for c in attack_curves])

    atk_mean = atk_mat.mean(axis=0)
    atk_p10 = np.quantile(atk_mat, 0.10, axis=0)
    atk_p90 = np.quantile(atk_mat, 0.90, axis=0)
    ranks = np.arange(1, n + 1)

    plt.figure(figsize=(10, 3))
    plt.plot(ranks, base, label="Baseline", linewidth=1.4)
    plt.plot(ranks, atk_mean, label="Attack mean", linewidth=1.4)
    plt.fill_between(ranks, atk_p10, atk_p90, alpha=0.25, label="Attack 10–90%")
    plt.xlabel("Rank")
    plt.ylabel("GMM anomaly score")
    plt.xlim(1, n)
    plt.grid(alpha=0.3, linestyle="--", linewidth=0.5)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def plot_recall_box(user_recalls, comp_recalls, out_path):
    data = [user_recalls, comp_recalls]
    plt.figure(figsize=(4, 3))
    plt.boxplot(data, tick_labels=["user_recall", "comp_recall"], whis=1.5)
    plt.ylabel("Recall@100")
    plt.grid(axis="y", alpha=0.3, linestyle="--", linewidth=0.5)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def plot_recall_cdf(user_recalls, comp_recalls, out_path):
    u_sorted = np.sort(user_recalls)
    c_sorted = np.sort(comp_recalls)
    u_cdf = np.arange(1, len(u_sorted) + 1) / len(u_sorted)
    c_cdf = np.arange(1, len(c_sorted) + 1) / len(c_sorted)

    plt.figure(figsize=(6, 3))
    plt.plot(u_sorted, u_cdf, label="User recall")
    plt.plot(c_sorted, c_cdf, label="Computer recall")
    plt.xlabel("Recall@100")
    plt.ylabel("CDF")
    plt.grid(alpha=0.3, linestyle="--", linewidth=0.5)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def plot_recall_pdf(user_recalls, comp_recalls, out_path):
    # KDE가 잘 안 되는 경우 대비하여 값이 하나뿐이면 그대로 점만 찍는다
    plt.figure(figsize=(6, 3))

    if len(user_recalls) > 1:
        u_kde = gaussian_kde(user_recalls)
        xs = np.linspace(0.0, max(user_recalls.max(), 1e-3) * 1.2, 200)
        plt.plot(xs, u_kde(xs), label="User Recall@100")
    else:
        plt.scatter(user_recalls, [1.0], label="User Recall@100")

    if len(comp_recalls) > 1:
        c_kde = gaussian_kde(comp_recalls)
        xs2 = np.linspace(0.0, max(comp_recalls.max(), 1e-3) * 1.2, 200)
        plt.plot(xs2, c_kde(xs2), label="Computer Recall@100")
    else:
        plt.scatter(comp_recalls, [1.0], label="Computer Recall@100")

    plt.xlabel("Recall@100")
    plt.ylabel("Density")
    plt.grid(alpha=0.3, linestyle="--", linewidth=0.5)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def save_summary_table(user_recalls, comp_recalls, out_csv):
    def stats(x):
        return {
            "n_windows": len(x),
            "mean": np.mean(x),
            "median": np.median(x),
            "std": np.std(x),
            "min": np.min(x),
            "max": np.max(x),
            "frac_gt0": float(np.mean(x > 0.0)),
        }

    table = pd.DataFrame(
        {
            "user_recall": stats(user_recalls),
            "comp_recall": stats(comp_recalls),
        }
    )
    table.to_csv(out_csv)
    return table


def main():
    (
        baseline_metrics,
        baseline_curve,
        attack_metrics,
        attack_curves,
        attack_tags,
    ) = collect_runs(SVD_DIR)

    user_recalls, comp_recalls = compute_recalls(attack_metrics)

    plot_anomaly_curve(
        baseline_curve,
        attack_curves,
        os.path.join(OUT_DIR, "svd_anomaly_summary.png"),
    )
    plot_recall_box(
        user_recalls,
        comp_recalls,
        os.path.join(OUT_DIR, "svd_recall_boxplot.png"),
    )
    plot_recall_cdf(
        user_recalls,
        comp_recalls,
        os.path.join(OUT_DIR, "svd_recall_cdf.png"),
    )
    plot_recall_pdf(
        user_recalls,
        comp_recalls,
        os.path.join(OUT_DIR, "svd_recall_pdf.png"),
    )

    save_summary_table(
        user_recalls,
        comp_recalls,
        os.path.join(OUT_DIR, "svd_summary_table.csv"),
    )


if __name__ == "__main__":
    main()
