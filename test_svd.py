import os
import time
import json
import gzip
import numpy as np
import pandas as pd
import networkx as nx
from tqdm import tqdm
from collections import defaultdict
from scipy.sparse import coo_matrix
from sklearn.decomposition import TruncatedSVD
from sklearn.mixture import GaussianMixture
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt


# ============================================================
# 0. 경로 및 설정
# ============================================================

DATA_DIR = r"C:\Datasets\NANL"
AUTH_PATH = os.path.join(DATA_DIR, "auth.txt.gz")
RED_PATH = os.path.join(DATA_DIR, "redteam.txt.gz")

OUTPUT_DIR = "lanl_svd_experiment"
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_ROWS = 2_000_000          # auth 로드 제한
WINDOW = 12 * 3600            # 12시간 분석
SVD_DIM = 32                  # 그래프 임베딩 차원


# ============================================================
# 1. 데이터 로딩
# ============================================================

def load_auth_time_window(start_t, end_t, max_rows):
    col = [
        "time", "src_user", "dst_user",
        "src_computer", "dst_computer",
        "auth_type", "logon_type", "auth_orientation", "outcome"
    ]

    print(f"[AUTH] Load {start_t} ~ {end_t}")
    df_list, rows = [], 0

    for chunk in pd.read_csv(
        AUTH_PATH, compression="gzip",
        names=col, header=None, dtype=str,
        chunksize=200_000
    ):
        chunk["time"] = chunk["time"].astype(int)
        mask = (chunk["time"] >= start_t) & (chunk["time"] < end_t)
        chunk = chunk[mask]

        df_list.append(chunk)
        rows += len(chunk)
        if rows >= max_rows:
            break

    if not df_list:
        return pd.DataFrame(columns=col)

    df = pd.concat(df_list, ignore_index=True)
    print(f"[AUTH] Loaded rows = {len(df):,}")
    return df


def load_redteam():
    col = ["time", "user", "src_computer", "dst_computer"]
    df = pd.read_csv(
        RED_PATH, compression="gzip",
        names=col, header=None, dtype=str
    )
    df["time"] = df["time"].astype(int)
    return df


# ============================================================
# 2. 레드팀 공격이 실제 발생한 시간대 자동 탐색
# ============================================================

def detect_redteam_windows(red_df, window=WINDOW):
    """
    redteam이 존재하는 시간대(start,end)를 자동 탐지함.
    """
    if red_df.empty:
        return []

    min_t, max_t = red_df["time"].min(), red_df["time"].max()

    windows = []
    t = min_t
    while t < max_t:
        sub = red_df[(red_df["time"] >= t) & (red_df["time"] < t + window)]
        if len(sub) > 0:
            windows.append((t, t + window))
        t += window
    return windows


# ============================================================
# 3. 그래프 기반 이상 탐지
# ============================================================

def build_graph(df):
    df = df.copy()
    df = df[
        (df["src_computer"].notna()) &
        (df["dst_computer"].notna()) &
        (df["src_computer"] != df["dst_computer"])
    ]
    df = df[df["outcome"].str.lower() == "success"]

    g = nx.DiGraph()
    print("[GRAPH] building...")
    for _, r in tqdm(df.iterrows(), total=len(df)):
        s, d = r["src_computer"], r["dst_computer"]
        if not g.has_edge(s, d):
            g.add_edge(s, d, weight=0)
        g[s][d]["weight"] += 1

    print(f"[GRAPH] nodes={g.number_of_nodes():,}, edges={g.number_of_edges():,}")
    return g


def embed_graph_svd(g, dim=SVD_DIM):
    nodes = list(g.nodes())
    idx = {n: i for i, n in enumerate(nodes)}

    rows, cols, data = [], [], []
    for s, d, w in g.edges(data=True):
        rows.append(idx[s])
        cols.append(idx[d])
        data.append(float(w["weight"]))

    A = coo_matrix((data, (rows, cols)), shape=(len(nodes), len(nodes)))

    k = min(dim, len(nodes)-1)
    print(f"[SVD] running dim={k}")
    svd = TruncatedSVD(n_components=k, random_state=42)
    emb = svd.fit_transform(A)

    df = pd.DataFrame(emb, index=nodes)
    df.index.name = "computer"
    return df


def gmm_scores(emb_df, comp=4):
    X = emb_df.values.astype(np.float64)

    gmm = GaussianMixture(
        n_components=comp, covariance_type="full",
        reg_covar=1e-3, n_init=3, max_iter=300,
        random_state=42
    )
    gmm.fit(X)
    scores = -gmm.score_samples(X)

    out = emb_df.copy()
    out["gmm_score"] = scores
    return out.sort_values("gmm_score", ascending=False)


# ============================================================
# 4. 사용자 행동 기반 이상 탐지
# ============================================================

def build_user_features(df):
    df = df.copy()
    df["time"] = df["time"].astype(int)
    df["hour"] = (df["time"]//3600) % 24
    df["src_user"] = df["src_user"].fillna("UNKNOWN")
    df["dst_user"] = df["dst_user"].fillna("UNKNOWN")

    g = df.groupby("src_user")
    feat = pd.DataFrame({
        "total_events": g.size(),
        "success_ratio": g["outcome"].apply(lambda x: (x.str.lower()=="success").mean()),
        "fail_ratio": g["outcome"].apply(lambda x: (x.str.lower()=="failure").mean()),
        "unique_dst": g["dst_computer"].nunique(),
        "night_ratio": g["hour"].apply(lambda h: ((h<6)|(h>=20)).mean()),
        "self_user_ratio": g.apply(lambda x: (x["src_user"]==x["dst_user"]).mean())
    })
    return feat.fillna(0.0)


def iforest_scores(feat_df):
    X = feat_df.values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=300, contamination="auto",
        random_state=42, n_jobs=-1
    )
    iso.fit(Xs)

    s = -iso.decision_function(Xs)
    out = feat_df.copy()
    out["iforest_score"] = s

    # z-score 기반 SHAP-like 기여도
    z = np.abs(Xs)
    contrib = pd.DataFrame(
        z, columns=[f"z_{c}" for c in feat_df.columns],
        index=feat_df.index
    )
    return out.sort_values("iforest_score", ascending=False), contrib


# ============================================================
# 5. redteam 정량 평가
# ============================================================

def evaluate_hits(rank_df, red_list, topk):
    top = rank_df.head(topk).index.tolist()
    hits = red_list.intersection(top)
    return len(hits), len(red_list)


# ============================================================
# 6. 시각화
# ============================================================

def plot_curve(values, title, path):
    plt.figure(figsize=(10,4))
    plt.plot(values)
    plt.title(title)
    plt.xlabel("rank")
    plt.ylabel("score")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


# ============================================================
# 7. 메인 실험
# ============================================================

def run_window(start, end, red_df, tag):
    print(f"\n=== RUN WINDOW {tag}: {start}~{end} ===")

    auth = load_auth_time_window(start, end, MAX_ROWS)
    if auth.empty:
        print("empty window.")
        return None

    # 그래프 기반
    g = build_graph(auth)
    emb = embed_graph_svd(g)
    gmm = gmm_scores(emb)

    # 사용자 기반
    feat = build_user_features(auth)
    iforest, contrib = iforest_scores(feat)

    # redteam 평가
    rsub = red_df[(red_df["time"]>=start)&(red_df["time"]<end)]
    red_users = set(rsub["user"].dropna()) if not rsub.empty else set()
    red_comps = set(rsub["src_computer"].dropna()) | set(rsub["dst_computer"].dropna())

    hit_u_100, total_u = evaluate_hits(iforest, red_users, 100)
    hit_c_100, total_c = evaluate_hits(gmm, red_comps, 100)

    # 저장
    wdir = os.path.join(OUTPUT_DIR, tag)
    os.makedirs(wdir, exist_ok=True)

    gmm.to_csv(os.path.join(wdir, "computer_scores.csv"))
    iforest.to_csv(os.path.join(wdir, "user_scores.csv"))
    contrib.to_csv(os.path.join(wdir, "user_feature_contrib.csv"))

    plot_curve(gmm["gmm_score"].values, "GMM Computer Anomaly", os.path.join(wdir,"gmm_curve.png"))
    plot_curve(iforest["iforest_score"].values, "IForest User Anomaly", os.path.join(wdir,"if_curve.png"))

    metrics = {
        "window": [start, end],
        "n_events": len(auth),
        "red_users": len(red_users),
        "red_computers": len(red_comps),
        "hit_user@100": hit_u_100,
        "total_reduser": total_u,
        "hit_comp@100": hit_c_100,
        "total_redcomp": total_c
    }

    # numpy.int64, numpy.float64 등 모두 Python 기본 타입으로 변환
    def to_python_type(obj):
        if isinstance(obj, dict):
            return {k: to_python_type(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [to_python_type(v) for v in obj]
        elif hasattr(obj, "item"):  # numpy scalar
            return obj.item()
        else:
            return obj

    metrics = to_python_type(metrics)

    with open(os.path.join(wdir,"metrics.json"),"w") as f:
        json.dump(metrics,f,indent=2)

    return metrics


def main():
    t0 = time.time()
    red = load_redteam()

    # 1) redteam 존재 구간 자동 탐지
    atk_windows = detect_redteam_windows(red)
    print("Detected attack windows:", atk_windows)

    # 2) baseline 구간 (공격 없는 랜덤 시간)
    # baseline은 첫날 0~12h로 설정
    base_start, base_end = 0, WINDOW

    # 3) 실행
    base = run_window(base_start, base_end, red, "baseline")

    atk_results = []
    for (s,e) in atk_windows:
        r = run_window(s, e, red, f"attack_{s}_{e}")
        atk_results.append(r)

    # README 생성
    readme = f"""
# LANL Experiment Result

- Baseline window: {base_start} ~ {base_end}
- Attack windows: {atk_windows}

각 실험 폴더에:
- computer_scores.csv
- user_scores.csv
- user_feature_contrib.csv
- gmm_curve.png
- if_curve.png
- metrics.json  
이 생성됨.

본 실험은 LANL auth/redteam 로그의  
그래프 기반(GMM) + 사용자 행동 기반(IForest) 이상 탐지를 수행하여  
baseline 대비 attack 구간에서의 이상치 상승을 관찰하는 목적.
"""
    with open(os.path.join(OUTPUT_DIR,"README.md"),"w",encoding="utf-8") as f:
        f.write(readme)

    print(f"\n=== DONE (total {time.time()-t0:.1f}s) ===")


if __name__ == "__main__":
    main()
