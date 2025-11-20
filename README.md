# LANL 로그 기반 그래프 + 사용자 행동 이상 탐지 실험

## 1. 목적

- Los Alamos National Laboratory(LANL) 공개 로그를 활용한 비지도 이상 탐지 실험 정리
- 연구계획서에서 제안한 두 축 구현
  - 관계(그래프) 기반 이상 탐지
  - 사용자 개별 행동 특징 기반 이상 탐지
- 실제 redteam 공격 구간에서 이상 점수가 얼마나 상승하는지 정량 평가
- 추후 논문 본 실험으로 확장하기 위한 프로토타입 코드 및 결과 정리

---

## 2. 데이터셋 개요

### 2.1 사용 데이터

- **LANL Cyber Security Dataset (UNSW 대신 최종 선택)**
  - 실제 내부망 환경에서 약 58일간 수집된 보안 로그
  - 본 실험에서 사용한 파일
    - `auth.txt.gz`
      - 인증 이벤트 로그
      - 스키마 예시  
        `time, srcUser, dstUser, srcComputer, dstComputer, authType, logonType, authOrientation, outcome`
    - `redteam.txt.gz`
      - 공격 레드팀 활동 로그
      - 스키마 예시  
        `time, user, srcComputer, dstComputer`
  - 원본 크기
    - 전체 `auth.txt.gz` 약 7GB 수준
    - 실험에서는 시간 구간을 잘라서 사용

### 2.2 사용 시간 구간

- 전체를 한 번에 사용하는 대신, **시간 윈도우 단위 실험**으로 설계
  - 예시
    - 베이스라인 구간: 공격이 없는 일반 구간 12시간
    - 공격 구간: `redteam` 로그가 존재하는 구간을 탐색하여 12시간 단위로 분할
- 윈도우 예시 (초 단위)
  - `baseline`: `[86400, 129600)` (Day 2 0시 ~ Day 2 12시)
  - `attack_1166400_1209600`: `[1166400, 1209600)` 등

---

## 3. 참고한 GitHub 프로젝트

LANL 데이터를 실제로 어떻게 전처리·그래프화·모델링하는지 참고하기 위해 여러 레포지토리 구조와 코드를 분석함.

- `woodrad/lanl-cyber-ml`
  - Spark 기반 전처리 및 ML 파이프라인 구조 참고
  - auth/redteam를 시간 기반으로 분할하는 방식, 공격 구간 설정 아이디어 참고
- `magdalenesuo/LANL_processing` (예시)
  - `auth.txt.gz`를 여러 파일로 분할하고 PyTorch 텐서로 변환하는 전처리 흐름 참고
  - 사용자·호스트·타임스텝 인덱싱 방식 참고
- `SheedZu/Latent-Position-Anomaly-Detection`
  - 그래프를 인접 행렬로 표현한 뒤 **SVD 기반 latent position**을 얻고, GMM으로 이상 점수를 주는 구조 참고
- `Cyber-LANL`, `dgraph-lanl-csr` 등
  - LANL 로그를 그래프로 다루는 관행 확인
  - 노드 타입(사용자, 호스트, 프로세스) 분리, 관계 정의 방식 참고

실제 레포지토리 코드는 그대로 복사하지 않고,  
위 아이디어를 바탕으로 **경량화된 실험용 파이프라인**으로 재구성한 형태.

---

## 4. 공통 실험 파이프라인

### 4.1 전처리

1. `auth.txt.gz` 부분 로딩
   - `pandas.read_csv(..., chunksize=...)`로 청크 단위 읽기
   - `time` 컬럼을 정수로 변환 후, 선택한 `[start, end)` 범위 필터링
   - 메모리 보호를 위해 `MAX_ROWS` 상한 적용  
     (예: 2,000,000 ~ 3,000,000 행 정도)

2. `redteam.txt.gz` 부분 로딩
   - 동일한 시간 범위로 필터링
   - 해당 윈도우에 공격 이벤트가 존재하는지 확인

3. 공통 컬럼 정리
   - `src_user`, `dst_user`, `src_computer`, `dst_computer` 정규화
   - `outcome` 소문자 변환 후 `success` / `failure` 플래그로 활용

---

### 4.2 그래프 기반 이상 탐지 흐름

1. **그래프 구성**
   - 노드: `src_computer`, `dst_computer`
   - 엣지: `src_computer → dst_computer`
   - 엣지 가중치: 해당 방향으로 성공 로그인(`outcome == "success"`) 발생 횟수
   - `NetworkX DiGraph` 사용

2. **그래프 임베딩**
   - 두 가지 실험 버전
     1. **SVD 기반 임베딩**
        - 인접 행렬(또는 희소 행렬)을 만들고 `TruncatedSVD` 적용
        - 각 컴퓨터를 32차원 벡터로 임베딩
     2. **Node2Vec 기반 임베딩**
        - random walk 기반 노드 임베딩
        - walk length, window size, p/q 등 하이퍼 파라미터는 노트북 성능 고려해 보수적으로 설정

3. **GMM 기반 노드 이상 점수**
   - `GaussianMixture(n_components=4)` 사용
   - 각 노드 임베딩 벡터에 대해 **음수 로그 우도(-log p(x))**를 이상 점수로 사용
   - 높은 점수일수록 “드문/비정상적인 위치”에 있는 노드로 해석
   - 출력
     - `computer_scores.csv`  
       `computer, dim_1, ..., dim_32, gmm_anomaly_score`

---

### 4.3 사용자 행동 기반 이상 탐지 흐름

1. **행동 특징 벡터 구성 (user behavior profile)**

   `src_user` 기준 그룹화 후 다음 특징 추출

   - `total_events`  
     해당 사용자 발행 인증 이벤트 수
   - `success_ratio` / `fail_ratio`  
     성공/실패 비율
   - `unique_dst_computers`  
     접속한 고유 목적지 컴퓨터 개수
   - `night_ratio`  
     야간 시간대(0~6시, 20~24시) 이벤트 비율
   - `self_user_ratio`  
     `src_user == dst_user` 비율 (자기 계정 사용 여부)

2. **IsolationForest 기반 비지도 이상 탐지**

   - 입력: 위 행동 특징 벡터를 `StandardScaler`로 표준화
   - 모델: `IsolationForest(n_estimators=400, contamination="auto")`
   - 출력
     - `iforest_anomaly_score`  
       클수록 “이상”으로 해석

3. **간단한 SHAP-like 설명 (z-score 기반)**

   - 각 사용자에 대해 표준화된 feature 값의 절댓값을 기여도로 사용
     - `z_total_events`, `z_unique_dst`, `z_night_ratio` 등
   - 결과 파일 예시: `user_feature_contrib.csv`
     - 각 사용자별로 어떤 특징이 얼마나 튀었는지 정량 확인 가능

---

### 4.4 redteam 기반 정량 평가 지표

각 시간 윈도우마다 redteam 로그를 이용해 아래 지표 계산

- `red_users`  
  - 해당 윈도우에 등장한 공격 사용자 수
- `red_computers`  
  - 공격에 사용된 src/dst 컴퓨터 수
- `hit_user@100` / `hit_comp@100`  
  - 사용자/컴퓨터 이상 순위 상위 100개 안에 redteam 대상이 몇 개나 들어왔는지
- `metrics.json` 예시 구조
  ```json
  {
    "window": [1166400, 1209600],
    "n_events": 2173006,
    "n_graph_nodes": 8544,
    "n_users": 14290,
    "red_users": 21,
    "red_computers": 37,
    "hit_user@100": 3,
    "hit_comp@100": 5
  }
