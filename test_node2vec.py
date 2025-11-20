import os
import json
from typing import List, Tuple, Dict

import numpy as np
import pandas as pd
import networkx as nx
from tqdm import tqdm
from sklearn.decomposition import TruncatedSVD
from sklearn.mixture import GaussianMixture
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scipy.sparse import coo_matrix
import matplotlib.pyplot as plt

# Node2Vec 임베딩을 위해 gensim 사용 (설치 필요: pip install gensim)
try:
    from gensim.models import Word2Vec
    HAS_GENSIM = True
except ImportError:
    HAS_GENSIM = False


# ==========================
# 0. 경로 & 전역 설정
# ==========================

# LANL 데이터 위치 (auth.txt.gz, redteam.txt.gz 있는 폴더로 수정)
DATA_DIR = r"C:\Datasets\NANL"
AUTH_PATH = os.path.join(DATA_DIR, "auth.txt.gz")
RED_PATH = os.path.join(DATA_DIR, "redteam.txt.gz")

# 한 윈도우 길이 (초 단위) – 기본 12시간
WINDOW_SECONDS = 12 * 3600

# auth 최대 로딩 행수 (메모리 보호용)
MAX_ROWS = 3_000_000

# 결과 저장 루트
OUTPUT_ROOT = "lanl_node2vec_experiment"
os.makedirs(OUTPUT_ROOT, exist_ok=True)


# ==========================
# 유틸: numpy 타입 → Python 기본타입
# ==========================

def to_native(obj):
    """
    metrics.json 저장 시 numpy 타입을 Python 기본 타입으로 변환.
    np.int64, np.float32 등은 json이 그대로 못 쓰기 때문에
    재귀적으로 int/float로 바꿔준다.
    """
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, dict):
        return {k: to_native(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_native(v) for v in obj]
    return obj


# ==========================
# 1. 데이터 로딩 & redteam 윈도우 탐지
# ==========================

def load_redteam(path: str) -> pd.DataFrame:
    """
    LANL redteam.txt.gz 전체 로딩.
    컬럼: time, user, src_computer, dst_computer
    """
    cols = ["time", "user", "src_computer", "dst_computer"]
    print(f"[RED] load redteam from {path}")
    df = pd.read_csv(
        path,
        compression="gzip",
        names=cols,
        header=None,
        dtype=str
    )
    df["time"] = df["time"].astype(int)
    df = df.sort_values("time").reset_index(drop=True)
    print(f"[RED] rows={len(df):,}, time range=[{df['time'].min()}, {df['time'].max()}]")
    return df


def detect_attack_windows(red_df: pd.DataFrame, window_seconds: int) -> List[Tuple[int, int]]:
    """
    redteam 이벤트가 존재하는 시간대만 골라서
    일정 길이(window_seconds)의 윈도우로 나눈다.

    예) window_seconds = 12h -> redteam 이벤트가 포함된 각 12시간 구간을 리턴.
    """
    if red_df.empty:
        return []

    times = red_df["time"].values
    t_min = int(times.min())
    t_max = int(times.max())

    windows = []
    cur_start = (t_min // window_seconds) * window_seconds
    cur_end = cur_start + window_seconds

    while cur_start <= t_max:
        mask = (times >= cur_start) & (times < cur_end)
        if mask.any():
            windows.append((cur_start, cur_end))
        cur_start = cur_end
        cur_end = cur_start + window_seconds

    print("[RED] detected attack windows:", windows)
    return windows


def load_auth_subset(path: str, start: int, end: int, max_rows: int) -> pd.DataFrame:
    """
    auth.txt.gz 에서 [start, end) 시간 구간만 읽어서 반환.

    스키마:
      time, srcUser, dstUser, srcComputer, dstComputer,
      authType, logonType, authOrientation, outcome
    """
    cols = [
        "time", "src_user", "dst_user",
        "src_computer", "dst_computer",
        "auth_type", "logon_type", "auth_orientation", "outcome"
    ]
    print(f"[AUTH] Load {start} ~ {end}")
    chunks = []
    read_rows = 0

    for chunk in pd.read_csv(
        path,
        compression="gzip",
        names=cols,
        header=None,
        dtype=str,
        chunksize=200_000
    ):
        chunk["time"] = chunk["time"].astype(int)
        mask = (chunk["time"] >= start) & (chunk["time"] < end)
        chunk = chunk[mask]

        if chunk.empty:
            read_rows += len(chunk)
            if read_rows >= max_rows:
                break
            continue

        chunks.append(chunk)
        read_rows += len(chunk)
        if read_rows >= max_rows:
            break

    if not chunks:
        raise RuntimeError(f"[AUTH] no rows in window {start}~{end}")

    df = pd.concat(chunks, ignore_index=True)
    print(f"[AUTH] Loaded rows = {len(df):,}")
    return df


# ==========================
# 2. 그래프 구성 + SVD / Node2Vec 임베딩
# ==========================

def build_computer_graph(auth_df: pd.DataFrame) -> nx.DiGraph:
    """
    컴퓨터-컴퓨터 로그인 그래프 생성.

    - 노드: 컴퓨터
    - 엣지: src_computer → dst_computer
    - weight: 성공 로그인 횟수

    LANL_processing, cyber-LANL 코드들처럼
    host 간 인증 관계만 뽑아와서 가중치 그래프로 만든다.
    """
    print("[GRAPH] building...")
    g = nx.DiGraph()

    df = auth_df.copy()
    df = df[
        (df["src_computer"].notna()) &
        (df["dst_computer"].notna()) &
        (df["src_computer"] != df["dst_computer"])
    ]
    if "outcome" in df.columns:
        df = df[df["outcome"].str.lower() == "success"]

    for _, row in tqdm(df.iterrows(), total=len(df)):
        s = row["src_computer"]
        d = row["dst_computer"]
        if not g.has_edge(s, d):
            g.add_edge(s, d, weight=0)
        g[s][d]["weight"] += 1

    print(f"[GRAPH] nodes={g.number_of_nodes():,}, edges={g.number_of_edges():,}")
    return g


def spectral_embedding(g: nx.DiGraph, dim: int = 32) -> pd.DataFrame:
    """
    TruncatedSVD 기반 스펙트럴 임베딩.

    - 인접 행렬 A (host x host)를 희소 행렬로 만들고
      Lanczos 기반 SVD로 상위 k개 특이벡터를 추출한다.
    - Latent-Position-Anomaly-Detection, LANL_processing 에서 쓰던
      "그래프 → 행렬 → SVD" 아이디어의 경량 버전.
    """
    print("[SVD] running dim=", dim)
    nodes = list(g.nodes())
    if not nodes:
        raise RuntimeError("graph has no nodes")

    idx = {n: i for i, n in enumerate(nodes)}
    rows, cols, data = [], [], []

    for s, d, w in g.edges(data=True):
        i = idx[s]
        j = idx[d]
        rows.append(i)
        cols.append(j)
        data.append(float(w.get("weight", 1.0)))

    n = len(nodes)
    mat = coo_matrix((data, (rows, cols)), shape=(n, n), dtype=np.float64)
    k = max(2, min(dim, n - 1))
    svd = TruncatedSVD(n_components=k, random_state=42)
    emb = svd.fit_transform(mat)

    df = pd.DataFrame(emb, index=nodes)
    df.index.name = "computer"
    return df


def node2vec_embedding(g: nx.DiGraph,
                       dim: int = 32,
                       walk_length: int = 40,
                       num_walks: int = 10,
                       window: int = 5,
                       workers: int = 4) -> pd.DataFrame | None:
    """
    Node2Vec 스타일 랜덤 워크 + Word2Vec 임베딩.

    - p, q 는 1로 두고 단순 random-walk (DeepWalk)에 가깝게 구현.
    - gensim 이 설치되어 있지 않으면 None 리턴 → SVD만 사용.
    """
    if not HAS_GENSIM:
        print("[N2V] gensim not installed → skip node2vec embedding")
        return None

    print("[N2V] generating random walks...")
    nodes = list(g.nodes())
    neighbors = {n: list(g.neighbors(n)) for n in nodes}

    walks = []
    rng = np.random.default_rng(42)

    for n in tqdm(nodes):
        for _ in range(num_walks):
            walk = [n]
            cur = n
            for _ in range(walk_length - 1):
                neigh = neighbors.get(cur, [])
                if not neigh:
                    break
                cur = rng.choice(neigh)
                walk.append(cur)
            walks.append(walk)

    print("[N2V] training Word2Vec...")
    model = Word2Vec(
        sentences=walks,
        vector_size=dim,
        window=window,
        min_count=1,
        sg=1,          # skip-gram
        workers=workers,
        epochs=5
    )

    emb = []
    for n in nodes:
        emb.append(model.wv[n])
    emb = np.array(emb, dtype=np.float64)

    df = pd.DataFrame(emb, index=nodes)
    df.index.name = "computer"
    return df


def combine_graph_embeddings(svd_df: pd.DataFrame,
                             n2v_df: pd.DataFrame | None) -> pd.DataFrame:
    """
    SVD 임베딩 + Node2Vec 임베딩을 concat.

    - Node2Vec 결과가 없으면 SVD만 사용.
    - 둘 다 있으면 [SVD | Node2Vec] 를 붙여서 사용.
    """
    if n2v_df is None:
        print("[EMB] use SVD only")
        return svd_df.copy()

    common = svd_df.index.intersection(n2v_df.index)
    svd_common = svd_df.loc[common].values
    n2v_common = n2v_df.loc[common].values

    emb = np.concatenate([svd_common, n2v_common], axis=1)
    cols = [f"svd_{i}" for i in range(svd_common.shape[1])] + \
           [f"n2v_{i}" for i in range(n2v_common.shape[1])]

    df = pd.DataFrame(emb, index=common, columns=cols)
    df.index.name = "computer"
    print(f"[EMB] combined embedding shape={df.shape}")
    return df


def gmm_anomaly_scores(emb_df: pd.DataFrame, n_components: int = 4) -> pd.DataFrame:
    """
    GMM 기반 컴퓨터 노드 이상 점수.
    - 각 노드의 임베딩에 대해 full-covariance GMM을 학습하고,
      음수 log-likelihood(-log p(x)) 를 anomaly score 로 사용.
    """
    print("[GMM] fitting...")
    X = emb_df.values.astype(np.float64)
    gmm = GaussianMixture(
        n_components=n_components,
        covariance_type="full",
        reg_covar=1e-3,
        n_init=5,
        max_iter=500,
        random_state=42
    )
    gmm.fit(X)
    scores = -gmm.score_samples(X)

    out = emb_df.copy()
    out["gmm_score"] = scores
    out = out.sort_values("gmm_score", ascending=False)
    return out


# ==========================
# 3. 사용자 행동 벡터 + Isolation Forest
# ==========================

def build_user_features(auth_df: pd.DataFrame) -> pd.DataFrame:
    """
    사용자(src_user) 단위 행동 요약 벡터.

    - total_events: 전체 이벤트 수
    - success_ratio: 성공 비율
    - fail_ratio: 실패 비율
    - unique_dst: 접근한 고유 dst 컴퓨터 수
    - night_ratio: 야간(0~6, 20~24시) 이벤트 비율
    - self_user_ratio: src_user == dst_user 인 비율
    """
    print("[USER] build features...")
    df = auth_df.copy()
    df["time"] = df["time"].astype(int)
    df["src_user"] = df["src_user"].fillna("UNKNOWN")
    df["dst_user"] = df["dst_user"].fillna("UNKNOWN")

    hour = (df["time"] // 3600) % 24
    df["hour"] = hour

    g = df.groupby("src_user")
    total = g.size()
    success_ratio = g["outcome"].apply(lambda s: (s.str.lower() == "success").mean())
    fail_ratio = g["outcome"].apply(lambda s: (s.str.lower() == "failure").mean())
    unique_dst = g["dst_computer"].nunique()
    night_ratio = g["hour"].apply(lambda h: ((h < 6) | (h >= 20)).mean())
    self_ratio = g.apply(lambda x: (x["src_user"] == x["dst_user"]).mean())

    feat = pd.DataFrame({
        "total_events": total,
        "success_ratio": success_ratio,
        "fail_ratio": fail_ratio,
        "unique_dst": unique_dst,
        "night_ratio": night_ratio,
        "self_user_ratio": self_ratio
    })
    feat.index.name = "src_user"
    feat = feat.fillna(0.0)
    print(f"[USER] feature table shape={feat.shape}")
    return feat


def iforest_anomaly_scores(feat_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    IsolationForest 기반 사용자 이상 탐지.

    - IsolationForest 의 decision_function 을 사용하여
      iforest_score (클수록 이상) 산출
    - 각 feature 의 z-score 절댓값을 "SHAP-like" 설명값으로 사용
      (어떤 feature가 해당 user의 이상 점수에 많이 기여하는지)
    """
    print("[IF] fitting IsolationForest...")
    X = feat_df.values
    scaler = StandardScaler()
    X_std = scaler.fit_transform(X)

    clf = IsolationForest(
        n_estimators=400,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_std)

    # decision_function: 클수록 정상 → 부호 반전해서 이상도 점수
    scores = -clf.decision_function(X_std)

    result = feat_df.copy()
    result["iforest_score"] = scores
    result = result.sort_values("iforest_score", ascending=False)

    # z-score 절댓값을 user-feature 설명값으로 사용
    z_abs = np.abs(X_std)
    contrib = pd.DataFrame(
        z_abs,
        index=feat_df.index,
        columns=[f"z_{c}" for c in feat_df.columns]
    )

    return result, contrib


# ==========================
# 4. redteam 매칭 평가
# ==========================

def compute_redteam_metrics(
    comp_scores: pd.DataFrame,
    user_scores: pd.DataFrame,
    red_df: pd.DataFrame,
    start: int,
    end: int,
    top_k: int = 100
) -> Dict:
    """
    window [start, end) 에서 redteam 등장 user/컴퓨터를
    상위 top_k 리스트와 매칭해서 hit 수를 계산.
    """
    subset = red_df[(red_df["time"] >= start) & (red_df["time"] < end)]
    red_users = set(subset["user"].dropna())
    red_comps = set(subset["src_computer"].dropna()) | set(subset["dst_computer"].dropna())

    top_user_list = user_scores.head(top_k).index.tolist()
    top_comp_list = comp_scores.head(top_k).index.tolist()

    hit_users = red_users.intersection(top_user_list)
    hit_comps = red_comps.intersection(top_comp_list)

    metrics = {
        "window": [int(start), int(end)],
        "n_graph_nodes": int(comp_scores.shape[0]),
        "n_users": int(user_scores.shape[0]),
        "red_users": int(len(red_users)),
        "red_computers": int(len(red_comps)),
        "hit_user@100": int(len(hit_users)),
        "hit_comp@100": int(len(hit_comps)),
        "hit_user_ids": sorted(list(hit_users)),
        "hit_comp_ids": sorted(list(hit_comps)),
    }
    return metrics


# ==========================
# 5. 시각화
# ==========================

def plot_rank_curve(series: pd.Series, title: str, ylabel: str, path: str):
    """
    anomaly score를 랭크 기준으로 plot.
    - x축: rank (1이 최상위 이상 노드)
    - y축: anomaly score
    """
    plt.figure(figsize=(8, 4))
    vals = series.values
    plt.plot(range(1, len(vals) + 1), vals)
    plt.xlabel("Rank")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


# ==========================
# 6. 윈도우 단위 실행
# ==========================

def run_window(start: int, end: int, red_df: pd.DataFrame, tag: str):
    """
    하나의 시간 윈도우에 대해 전체 파이프라인 수행.

    - auth subset 로딩
    - 그래프 + SVD + Node2Vec → GMM 이상도
    - 사용자 행동 벡터 → IsolationForest 이상도
    - redteam 매칭 → metrics.json
    - computer_scores.csv / user_scores.csv / user_feature_contrib.csv / PNG 저장
    """
    print(f"\n=== RUN WINDOW {tag}: {start}~{end} ===")
    out_dir = os.path.join(OUTPUT_ROOT, tag)
    os.makedirs(out_dir, exist_ok=True)

    # 1) 데이터
    auth_df = load_auth_subset(AUTH_PATH, start, end, MAX_ROWS)

    # 2) 그래프 기반 이상 탐지
    g = build_computer_graph(auth_df)
    svd_df = spectral_embedding(g, dim=32)
    n2v_df = node2vec_embedding(g, dim=32) if g.number_of_nodes() > 0 else None
    emb_df = combine_graph_embeddings(svd_df, n2v_df)
    comp_scores = gmm_anomaly_scores(emb_df, n_components=4)

    # 3) 사용자 행동 기반 이상 탐지
    feat_df = build_user_features(auth_df)
    user_scores, contrib_df = iforest_anomaly_scores(feat_df)

    # 4) redteam 평가
    metrics = compute_redteam_metrics(comp_scores, user_scores, red_df, start, end, top_k=100)

    # 5) 결과 저장
    comp_scores.to_csv(os.path.join(out_dir, "computer_scores.csv"))
    user_scores.to_csv(os.path.join(out_dir, "user_scores.csv"))
    contrib_df.to_csv(os.path.join(out_dir, "user_feature_contrib.csv"))

    plot_rank_curve(
        comp_scores["gmm_score"],
        title=f"GMM Computer Anomaly ({tag})",
        ylabel="GMM anomaly score",
        path=os.path.join(out_dir, "gmm_curve.png")
    )
    plot_rank_curve(
        user_scores["iforest_score"],
        title=f"IForest User Anomaly ({tag})",
        ylabel="IForest anomaly score",
        path=os.path.join(out_dir, "if_curve.png")
    )

    with open(os.path.join(out_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(to_native(metrics), f, indent=2)

    print(f"[SAVE] {tag} done → {out_dir}")
    return metrics


# ==========================
# 7. 메인: baseline + attack 윈도우
# ==========================

def main():
    print("=== LANL Node2Vec Experiment ===")
    red_df = load_redteam(RED_PATH)
    attack_windows = detect_attack_windows(red_df, WINDOW_SECONDS)

    # baseline: 첫 공격 이전 12시간 (redteam 없는 구간)
    if attack_windows:
        first_attack_start = attack_windows[0][0]
        baseline_start = max(0, first_attack_start - WINDOW_SECONDS)
        baseline_end = first_attack_start
    else:
        baseline_start, baseline_end = 0, WINDOW_SECONDS

    baseline_metrics = run_window(baseline_start, baseline_end, red_df, "baseline")

    all_metrics = {"baseline": baseline_metrics, "attacks": []}

    for (s, e) in attack_windows:
        tag = f"attack_{int(s)}_{int(e)}"
        m = run_window(int(s), int(e), red_df, tag)
        all_metrics["attacks"].append(m)

    # 전체 요약 저장
    with open(os.path.join(OUTPUT_ROOT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(to_native(all_metrics), f, indent=2)

    print("=== DONE ===")
    print("results root:", OUTPUT_ROOT)


if __name__ == "__main__":
    main()
