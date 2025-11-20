# LANL Log-based Graph Anomaly Detection  
(Computer–Computer Graph SVD 방식, Node2Vec 비교 포함)

---

## 1. 실험 목적

대규모 Windows 도메인 환경에서 발생하는 인증 로그(auth.txt.gz)를  
**그래프 구조로 변환하고**,  
이 구조의 변화로부터 **공격(레드팀) 발생 시점의 이상행위를 식별**하는 것이 목적.

- 인증 로그 → 컴퓨터 간 이동(edge)로 그래프 구성  
- 그래프 임베딩(SVD / Node2Vec) → 노드별 이상 점수 계산  
- 사용자(User) 단위 행동 특징 벡터 → IsolationForest로 비지도 이상 탐지  
- 레드팀(redteam.txt.gz)이 실제 존재하는 시간대 구간을 자동 탐지하여  
  “정상 구간 vs 공격 구간”의 이상 점수 양상 비교  
- 각 실험은 **동일 스크립트로 재현 가능**하게 구성  

---

## 2. 사용 데이터셋

### LANL Cyber Security Dataset  
미국 Los Alamos National Laboratory(LANL)에서 제공한  
대규모 현실 기반 사이버보안 이벤트 데이터셋.

본 실험에서는 다음 두 파일만 사용:

| 파일명 | 설명 |
|-------|------|
| `auth.txt.gz` | 모든 인증 시도 로그 (src_user, src_computer, dst_computer 등 9개 필드) |
| `redteam.txt.gz` | 실제 공격자 활동 로그. 특정 일자·시간대에만 존재 |

1회 전체 크기는 약 **22GB** 수준.  
본 실험에서는 메모리 한계와 노트북 장비 조건을 고려하여  
각 기간(window)별로 **20~50만 행 단위 chunk loading** 방식으로 처리

---

## 3. 배경 및 참고한 기존 연구·레포

이번 실험 설계 시 다음 오픈소스 기반 실험 흐름을 참고함:

1) **Latent-Position Anomaly Detection (SVD 기반)**  
   - 노드 간 adjacency matrix → 저차원 SVD → GMM 기반 anomaly score  
   - LANL 그래프 연구에서 자주 사용되는 구조

2) **Node2Vec 기반 LANL 실험 레포**  
   - 그래프 탐색 기반 임베딩(node2vec)으로 공격 구간 분리  
   - 랜덤워커 기반 node embedding

3) **LANL preprocessing 깃허브 레포들**  
   - auth 로그 컬럼 매핑 방식  
   - redteam 시간대 존재 패턴  
   - LANL 로그의 소스/목적지 컴퓨터 id 규칙  
   - 그래프 구성 관행(동일 컴퓨터 제외, success event 중심)

4) **dgraph-lanl-csr 레포**  
   - LANL 데이터를 CSR 형태 그래프 변환  
   - 예측 실험에 필수적인 전처리 구조 참고

5) **LANL cyber ML baseline 레포**  
   - LANL 로그를 분 단위 혹은 시간 단위로 나누어  
     event count, host 이동 다변량 특징을 구축하는 방식 등 참고

---

## 4. 실험 전체 구조

본 레포는 두 종류의 실험을 병행하였고,  
최종적으로 **SVD 기반 그래프 실험**을 중심으로 분석 정리함:

### ◆ 실험 A: SVD 기반 컴퓨터–컴퓨터 그래프 임베딩  
- auth 로그 → (src_computer → dst_computer) directed edge  
- success 로그인만 사용  
- adjacency matrix 생성  
- Truncated SVD (dim=32)  
- Gaussian Mixture Model로 이상 점수 산출  
- 사용자 특징벡터 + IsolationForest 병행

### ◆ 실험 B: Node2Vec 그래프 임베딩 비교  
- 동일한 그래프 구조를 node2vec으로 임베딩  
- 동일한 방식으로 top-K anomaly에서 redteam hit 비교  
- SVD 대비 장점/단점 비교 분석 포함

---

## 5. 결과 디렉토리 구조

본 레포는 다음 형태를 갖음:

```
lanl_final_experiment/
│ baseline/
│   ├─ metrics.json
│   ├─ graph_degree_hist.png
│   ├─ gmm_anomaly_hist.png
│   └─ user_feature_hist.png
│ attack_1058085_1101285/
│   ├─ metrics.json
│   ├─ computer_scores.csv
│   ├─ user_scores.csv
│   ├─ top_anomalies.png
│   ├─ graph_degree_hist.png
│   ├─ gmm_anomaly_hist.png
│   └─ user_feature_hist.png
│ ...
```

Node2Vec 실험도 같은 구조를 따름.

---

## 6. 주요 실험 결과 요약

### 6-1. baseline (정상 구간)

사용된 시간 구간: **0–43,200초 (12시간)**  
- redteam 이벤트 없음  
- 그래프는 주로 정상적인 컴퓨터 간 이동 패턴으로 구성됨

**참고 이미지 삽입 위치:**  
```
![baseline-degree](baseline/graph_degree_hist.png)
```

---

### 6-2. 대표 공격 시간대 #1  
구간: **1058085–1101285초**

#### (A) SVD 기반 결과  
- redteam 사용자 수 7명  
- top-100 anomaly scoring에서 실제 공격 사용자 1명 포함  
- random expectation 대비 약 **4.2× 높은 hit**  
- 컴퓨터 노드 기준 anomaly score도 급격한 상승 패턴


```
<img width="1000" height="400" alt="if_curve" src="https://github.com/user-attachments/assets/dc57c3c3-1a2b-44b2-aaf6-b64feb23292e" />
<img width="1000" height="400" alt="gmm_curve" src="https://github.com/user-attachments/assets/194dbb03-0687-412e-b122-1f3c11b17406" />
```

#### 정량적 분석  
- 사용자 anomaly recall @100 = 14.3%  
- 사용자 random expectation = 3.4%  
- 컴퓨터 anomaly recall @100 = 14.7%  
- 컴퓨터 random expectation = 3.2%  
→ 일반적인 확률적 기대 대비 명확하게 높음

---

### 6-3. 대표 공격 시간대 #2 (Node2Vec)

구간: **1166400–1209600초**

#### (B) Node2Vec 기반 결과  
- redteam 사용자 수 7명  
- anomaly recall @100 = 14.3%  
- random expectation = 8.1%  
→ baseline 대비 anomaly 쏠림 존재  
→ 그러나 SVD 대비 공격 신호 분리가 약함(분포 분리도 차이 때문)

```
<img width="800" height="400" alt="if_curve" src="https://github.com/user-attachments/assets/6c9f4bcc-49cc-4eca-9d90-1400c3efa0d8" />
<img width="800" height="400" alt="if_curve" src="https://github.com/user-attachments/assets/9a74b1b2-a9bc-41fe-98a7-805cd495eaa2" />

```

---

## 7. 실험 A(SVD) vs 실험 B(Node2Vec) 비교

| 항목 | SVD 기반 | Node2Vec 기반 |
|------|----------|----------------|
| 그래프 임베딩 방식 | 전역적 구조 반영(SVD) | 지역적 random walk 중심 |
| 점수 분포 | 공격 구간에서 급격히 분리 | 공격 구간에서도 baseline과 일부 겹침 |
| redteam 점수 상위권 포함 | 명확한 상승 패턴 | 상승하나 변별력 약함 |
| 계산 시간 | 매우 빠름 (노트북환경 적합) | SVD 대비 오래 걸림 |
| 구현 단순성 | 높음 | 파라미터 튜닝 필요 |

---

## 8. 분석 및 해석

### (1) LANL 공격 시간대의 특징
- redteam 활동은 컴퓨터 간 lateral movement를 유발  
- 평소보다 edge가 비정상적 방향으로 증가  
- 이 패턴은 adjacency matrix에서 rank 변화를 유발  
→ SVD 임베딩에서 공격 노드만 특이점(outlier)로 분리됨

### (2) 사용자 행동 기반 특징(Behavior Vectors)
- total event count  
- night ratio  
- unique dst computers 수  
- self-user 이벤트 비율 등  
IsolationForest에서  
공격 사용자들의 **feature-level 편차가 압도적으로 높음**이 관찰됨.

### (3) Node2Vec의 한계
- LANL 그래프는 하루 단위에서도 5천~1만 노드에 달함  
- random walk 기반 임베딩은  
  공격 패턴이 “국지적”으로만 생기면 분리가 약해짐  
- 논문 목적의 “명확한 패턴 분리”에는 SVD가 더 적합

---

## 9. 정리

1) **Main Experiment:**  
   - SVD 기반 그래프 anomaly detection  
   - computer-level + user-level 결합  
   - redteam 시간대에서 분명한 anomaly 상승 그래프 포함

2) **Ablation Study:**  
   - Node2Vec anomaly 비교  
   - 그래프 구조 기반 방식의 차이를 논리적으로 설명 가능

---

