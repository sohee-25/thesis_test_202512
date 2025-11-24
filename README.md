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

Node2Vec 실험도 동일한 구조를 유지하며,  
SVD 대비 비교 목적의 최소 결과만 생성하였다.


---

## 6. 주요 실험 결과 요약

### 6-1. Baseline (정상 구간)

- 구간: **0–43,200초 (12시간)**
- redteam 이벤트 없음  
- 전체 그래프 구조는 정상 도메인 환경에서 흔히 관찰되는  
  “규칙적 인증 흐름(regular logon flows)” 중심이며  
  anomaly score(컴퓨터/사용자 모두)도 안정적으로 낮게 유지됨.

---

### 6-2. 대표 공격 구간 예시 (#1)

- 구간: **1058085–1101285초**

#### SVD 기반 결과 요약
- redteam 사용자 수: 7명  
- Top-100 anomaly 리스트 내 실제 공격 사용자 수: 1명  
- random expectation 대비 **높은 편의 recall**, 하지만  
  **전반적 분포는 baseline과 완전히 분리되지는 않음**
- 컴퓨터 anomaly score에서도 특정 공격 구간에서  
  **점수 상승(초기 rank 부근에서 급증)**은 관찰됨

#### 정량지표
| 항목 | 값 |
|------|------|
| User Recall@100 | 14.3% |
| User Random Expectation | 약 3.4% |
| Computer Recall@100 | 14.7% |
| Computer Random Expectation | 약 3.2% |

→ **랜덤보다는 분명히 높은 hit**,  
   그러나 공격 구간 전체에서 일관된 패턴이 나온다고 보기엔 어려움.
<img width="3121" height="1237" alt="svd_anomaly_curve_summary" src="https://github.com/user-attachments/assets/7cc03d82-df74-482d-b27b-a54939ea0ff7" />
<img width="2544" height="1237" alt="svd_recall_pdf" src="https://github.com/user-attachments/assets/81666a03-e185-4df1-9cda-e739fc55b18b" />
<img width="2600" height="1237" alt="svd_recall_cdf" src="https://github.com/user-attachments/assets/c3f68dad-ef14-4d71-9769-66d5252cac4e" />
<img width="2600" height="1391" alt="svd_recall_boxplot" src="https://github.com/user-attachments/assets/0d4a5437-ca01-40f1-9a5e-1aab7ca25828" />

---

### 6-3. Node2Vec 실험 (간단 비교)

Node2Vec은 **동일 그래프에서 최소 파라미터로만** 시험적으로 수행하였다.  
- 구간: **1166400–1209600초**
- User Recall@100 ≈ 14.3%  
- Random expectation 대비 상승은 있으나  
  **전반적 분리도는 SVD보다 더 약함**

Node2Vec은 random walk 기반이라  
LANL처럼 **노드 수가 많고 연결관계가 sparse한 그래프에서  
임베딩 안정성이 낮아지는 한계**가 그대로 나타났다.

본 레포에서는 Node2Vec을 “보조적 비교 실험” 수준으로 유지하고  
주요 분석은 SVD 중심으로 진행하였다.

---

## 7. SVD vs Node2Vec 비교

| 기준 | SVD 기반 | Node2Vec 기반 |
|------|----------|----------------|
| 반영되는 정보 | 전역 구조(global structure) | 지역 random walk(local structure) |
| 그래프 노이즈 영향 | 상대적으로 낮음 | 높음 |
| 공격 구간 분리도 | 일부 구간에서 상승 경향 | 상대적으로 약함 |
| 계산 비용 | 낮음 | 상대적으로 높음 |
| 파라미터 조정 | 거의 없음 | 다수 필요 |
| LANL 데이터 적합성 | 비교적 적합 | sparse·scale 문제로 제한적 |

→ 현재 실험 결과만 보면 **SVD가 LANL 로그 구조에 더 적합**  
→ Node2Vec은 튜닝 여지를 남기지만 baseline 수준의 안정성은 부족

---

## 8. 전체 분석 및 향후 방향

### (1) SVD 기반 이상탐지의 관찰 사항
- 공격 구간의 일부에서 anomaly score 상승이 분명히 존재함  
- 그러나 **모든 공격 구간에서 일관되게 높은 분리도**가 나타난 것은 아님  
- LANL 데이터 특성상 정상 로그 패턴의 변동도 크기 때문에  
  anomaly 척도가 “명확한 step-function 분리” 형태는 아님  
- 즉, **SVD는 일정 수준의 신호를 포착하지만 완전한 검출기라고 보기 어렵다**

### (2) 사용자 행동 특징(IForest) 분석
- 특정 공격 구간에서는 사용자의 행동 통계(total events, unique dst 등)만으로도  
  정상 대비 차이가 확인됨  
- 하지만 **사용자 수가 매우 많고 sparse하여**  
  Top-K 기준으로 anomaly를 강하게 분리하는 데는 한계가 있음

### (3) Node2Vec의 제한점
- LANL 그래프는 규모가 크고 sparse하기 때문에  
  random walk 기반 모델에서 흔히 발생하는  
  **임베딩 분산 불안정성**이 그대로 나타남  
- 실험 결과 또한 baseline·attack 간 분리도가 상대적으로 약했음

### (4) 결론 및 향후 모델 교체 고려
현재 실험 결과는  
- “SVD가 Node2Vec보다 상대적으로 안정적으로 신호를 잡아낸다” 정도의 의미는 있으나  
- **논문 수준에서 강하게 주장할 만큼의 높은 분리도는 아님**

따라서 후속 연구에서는 다음 모델을 검토할 필요가 있음:

#### 후보 모델
- **Graph Autoencoder (GAE) / Variational GAE**  
- **RGCN 기반 Log2Graph 계열 모델**  
- **Temporal Graph Networks (TGN)**  
- **Graph-based contrastive learning (GRACE 등)**  
- **LANL 연구에서 자주 사용되는 “Dynamic Graph Embedding” 기법**

이들은  
- 시계열 특성  
- 사용자-컴퓨터-프로세스 관계의 다중관계  
- 로그 시맨틱  
을 함께 고려할 수 있어 SVD보다 더 일관된 분리도를 기대할 수 있다.

---

## 요약

- 본 실험은 **LANL 로그에 대해 SVD 기반 그래프 이상 탐지 실험**을 재현·확인하는 목적  
- 일부 공격 구간에서 anomaly 상승이 존재하지만  
  전체적으로 “강한 분리도”라고 판단할 정도는 아님  
- Node2Vec은 baseline 실험으로는 적합하지 않음  
- 향후 GAE·RGCN·TGN 등 **심층 그래프 모델**로의 전환을 검토할 필요가 있음



