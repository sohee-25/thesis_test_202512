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

실험 결과는 다음과 같이 저장됨:

lanl_svd_experiment/
│ baseline/
│ ├─ metrics.json
│ ├─ gmm_curve.png
│ └─ if_curve.png
│ attack_1058085_1101285/
│ ├─ metrics.json
│ ├─ computer_scores.csv
│ ├─ user_scores.csv
│ ├─ user_feature_contrib.csv
│ ├─ gmm_curve.png
│ └─ if_curve.png
│ ...

Node2Vec 실험도 동일 구조로 저장됨:

lanl_node2vec_experiment/
│ baseline/
│ ├─ metrics.json
│ ├─ gmm_curve.png
│ └─ if_curve.png
│ attack_1166400_1209600/
│ ├─ metrics.json
│ ├─ gmm_curve.png
│ └─ if_curve.png
│ ...


---

## 6. 주요 실험 결과 요약

### 6-1. Baseline (정상 구간)

시간 구간: **0–43,200초 (12시간)**  
- redteam 이벤트 없음  
- 그래프 구조는 정상적인 내부 인증 패턴 중심  
- anomaly score 곡선이 비교적 완만함

<img width="1000" height="400" alt="if_curve" src="https://github.com/user-attachments/assets/11ae47d4-289a-4c69-b675-4f4f54f28226" />
<img width="1000" height="400" alt="gmm_curve" src="https://github.com/user-attachments/assets/97437adc-8bdb-4497-b4de-1c238e4b535d" />

---

### 6-2. 공격 구간 예시 #1 (SVD 기반)

시간 구간: **1058085–1101285초**

주요 특징:
- redteam 사용자 7명 등장  
- computer anomaly score 곡선에서 상위 노드 점수 값이 급격히 상승  
- user anomaly도 baseline 대비 상위권 분포 변화 존재  
- random expectation 대비 더 높은 hit 비율

<img width="1000" height="400" alt="if_curve" src="https://github.com/user-attachments/assets/754a9f46-4363-48e1-9c94-d87b7e50a48b" />
<img width="1000" height="400" alt="gmm_curve" src="https://github.com/user-attachments/assets/ea069266-3f44-412d-98d0-fda84b67f616" />

정량적 결과:
- 사용자 Recall@100 ≈ **14.3%**  
- 사용자 random 기대치 ≈ **3.4%**  
- 컴퓨터 Recall@100 ≈ **14.7%**  
- 컴퓨터 random 기대치 ≈ **3.2%**

---

### 6-3. 공격 구간 예시 #2 (Node2Vec)

시간 구간: **1166400–1209600초**

Node2Vec은 최소 파라미터 설정 상태로 시험적으로 실행
상승 패턴은 존재했으나 SVD에 비해 분리도는 약함

<img width="800" height="400" alt="if_curve" src="https://github.com/user-attachments/assets/7011574a-0d52-4f2b-9294-5bf4a9c9466a" />
<img width="800" height="400" alt="gmm_curve" src="https://github.com/user-attachments/assets/1d205fa7-c6d0-4420-8477-c5ae4ebe6c7e" />


핵심 요약:
- Recall@100 ≈ **14.3%**  
- random 기대치보다 높으나, SVD처럼 명확한 급상승 패턴은 아님  
- sparse LANL 그래프에서 random-walk 기반 임베딩의 안정성 한계가 나타남

---

## 7. SVD vs Node2Vec 비교

| 기준 | SVD 기반 | Node2Vec 기반 |
|------|----------|----------------|
| 반영 정보 | 그래프의 전역 구조 | 지역 random walk 구조 |
| sparse LANL 환경 안정성 | 비교적 안정적 | 분산 불안정성 높음 |
| 공격 구간 anomaly 분리도 | 일부 구간에서 명확한 상승 | 상대적으로 약함 |
| 계산 비용 | 낮음 | 상대적으로 높음 |
| 파라미터 의존성 | 낮음 | 높음 |
| 전체 적합성 | LANL 구조에 적합 | baseline 수준의 안정성 부족 |

Node2Vec은 “보조적 비교 실험”으로 유지하며,  
주요 분석은 SVD 결과를 중심으로 진행함

---

## 8. 전체 분석 및 향후 방향

### (1) SVD 기반 anomaly 관찰

공격 구간 일부에서 anomaly score 분포의 변동이 실제로 나타남  
일부 redteam 관련 노드가 상위 anomaly 영역으로 이동하는 패턴도 확인됨  
다만 모든 attack window에서 동일한 수준의 분리가 발생하지는 않음  
LANL 정상 로그 자체의 변동성이 크기 때문에, 특정 구간은 신호가 약하게 나타남

### (2) 사용자 행동 기반(IForest) 관찰

일부 window에서는 사용자 행동 통계량 변화가 상대적으로 명확함  
그러나 사용자 수가 매우 많고 데이터가 sparse해 상위 Top-K 기반 분리는 일정 수준에서 한계가 존재함  
추가 특징을 조합하거나 사용자–컴퓨터 관계를 함께 고려할 여지가 있어 보임

### (3) Node2Vec 비교 실험

LANL 그래프처럼 규모가 크고 연결이 희박한 경우 random-walk 기반 임베딩 안정성이 떨어질 수 있음  
이번 실험에서도 anomaly 상승 자체는 관찰되지만 SVD만큼 분리도는 나타나지 않음  
그래프 구조가 시계열성·다중 관계를 동시에 가지기 때문으로 보이며, 현재 실험에서는 참고용 수준으로 활용함

### (4) 향후 적용을 고려 중인 모델

현재 결과를 기준으로 보면 SVD 기반 접근이 상대적으로 안정적인 편이었지만  
LANL 데이터 특성상 일부 구간에서는 분리도가 충분히 크지 않은 문제도 확인됨  

기존 LANL 연구나 공개 레포에서 활용된 방법들을 참고하면  
다음과 같은 모델 방향을 추가로 검토해볼 여지가 있음  

- Graph Autoencoder(GAE) 계열  
- Relational-GCN(Log2Graph 계열에서 사용)  
- 시계열 기반 그래프 모델(TGN 등)

이들 모델은 시간적 변화나 다중 엔티티 관계를 함께 고려할 수 있어  
SVD에서 보이지 않는 신호를 포착할 가능성이 있음  

현재 장비 환경과 구현 부담을 고려하면  
GAE 계열이 상대적으로 접근성이 높고 재현도도 확보할 수 있는 선택지로 보임  
다만 실제 적용 가능성은 추가 테스트가 필요하며,  
이번 실험에서는 우선 SVD 기반 이상탐지의 동작 여부를 확인하는 데에 중점을 두었음

---





