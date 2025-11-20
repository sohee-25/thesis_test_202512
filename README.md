LANL 기반 그래프 사용자 행위 이상 탐지 실험
1. 프로젝트 개요

목적

Los Alamos National Laboratory(LANL) 인증 로그를 사용자–컴퓨터 그래프로 표현

그래프 임베딩 + 비지도 이상 탐지 모델로 공격 세션(redteam)을 얼마나 상위 랭크로 올릴 수 있는지 검증

“제로트러스트 환경에서 사용자 행위 기반 이상 탐지” 논문 실험 가능성 확인

실험 구성

실험 1: 스펙트럴 임베딩(Truncated SVD) + Isolation Forest

실험 2: Node2Vec 임베딩 + Isolation Forest

두 실험 모두 동일한 전처리 파이프라인, 동일한 redteam 공격 구간 사용

성능 지표: redteam 사용자/컴퓨터의 Top-100 anomaly rank 포함 개수

2. 데이터셋 설명

사용 데이터

auth.txt.gz

필드: time, srcUser, dstUser, srcComputer, dstComputer, authType, logonType, authOrientation, outcome

Kerberos 기반 인증 로그, 초 단위 타임스탬프, 성공/실패 결과 포함

redteam.txt.gz

필드: time, user, srcComputer, dstComputer

실제 공격 팀(red team)의 침투·가로채기 활동 로그

특정 며칠, 특정 시간대에만 존재

데이터 규모 (원본 기준 개략)

auth.txt.gz: 수십 GB, 수억 건 수준

redteam.txt.gz: 수천 건 수준

노트북 환경 제약 때문에 전체가 아니라 시간 윈도우 단위로 부분 샘플링

전처리에서 실제로 사용한 구간 예시

베이스라인 구간: time ∈ [0, 43,200) (최초 하루의 12시간)

공격 구간 예시 1 (SVD 실험): time ∈ [1,058,085, 1,101,285)

공격 구간 예시 2 (Node2Vec 실험): time ∈ [1,166,400, 1,209,600)

전체 코드에서는 redteam.txt.gz를 먼저 스캔해서 redteam이 실제로 등장하는 시간대를 자동으로 탐색하고, 그 구간들에 대해 반복 실험 수행

3. 참고한 공개 코드·연구 흐름

실험 설계와 구현은 다음 GitHub 프로젝트에서 아이디어와 구현 패턴을 참고해서 재구성한 것임.

LANL 전처리 파이프라인

LANL_processing

대용량 auth.txt.gz를 날짜·사용자·컴퓨터 기준으로 묶어서 압축된 피클/torch 텐서로 변환하는 파이프라인

이번 실험에서는 전체를 그대로 쓰기보다는,

chunk 기반 read_csv

시간 윈도우 필터

user / computer 인덱스 매핑 방식
를 참고해서 파이썬 단일 스크립트 버전으로 단순화

그래프 기반 이상 탐지 설계

Latent-Position-Anomaly-Detection

LANL 인증 로그를 user–computer 그래프로 표현

그래프의 인접 행렬/라플라시안에 SVD 또는 특징 벡터 축소를 적용해 latent position을 얻은 뒤,

Gaussian Mixture Model(GMM)으로 밀도 기반 이상 점수 계산

이번 실험 1(SVD) 의

“컴퓨터 그래프 → 희소 인접 행렬 → TruncatedSVD → GMM 스코어링” 흐름에 직접적인 참고

전체 파이프라인/모델 레포

lanl-cyber-ml, Cyber-LANL, dgraph-lanl-csr

Spark·Scala 기반 대규모 분산 처리, 특징 엔지니어링, 노드 임베딩, 분류/클러스터링 등 다양한 시도

구조적인 참고:

auth/redteam를 공통 포맷으로 통합

공격이 포함된 구간과 포함되지 않은 구간 비교

그래프 기반 특징과 사용자 집계 기반 특징을 함께 사용하는 흐름

이번 레포에서는 그 구조를 단일 파이썬 스크립트 + 노트북 수준으로 축소한 형태

4. 공통 전처리 파이프라인
4.1 auth 로그 로딩

함수 개요

load_auth_subset(path, start_time, end_time, max_rows)

pandas.read_csv(..., chunksize=200_000) 사용

time 컬럼을 int로 변환한 뒤 start_time ≤ time < end_time 필터

max_rows 넘는 시점에서 조기 종료

실험 예시

베이스라인 구간 [0, 43,200)

약 2,000,000건 로딩

공격 구간 예시

[1,058,085, 1,101,285) 구간에서 약 1,400,000건 수준

4.2 redteam 로딩 및 공격 구간 탐지

함수 개요

load_redteam(path)

redteam.txt.gz 전체 로딩 후 time 기준 정렬

공격 시간대 탐지 로직 요약

redteam time을 기준으로, 일정 크기(예: 43,200초 ≒ 12시간)의 슬라이딩 윈도우를 움직이며

윈도우 안에 redteam 이벤트가 일정 개수 이상 들어오면 “공격 윈도우”로 지정

예시 탐지 결과

[1,058,085, 1,101,285)

[1,166,400, 1,209,600)

그 외 여러 구간

5. 실험 1: SVD 기반 Latent Position + Isolation Forest
5.1 그래프·모델 구조

그래프 정의

노드: src_computer, dst_computer

엣지: src_computer → dst_computer

엣지 weight: 해당 구간에서 성공 인증(outcome=="Success") 횟수

임베딩

희소 인접 행렬 A 구성 (n_nodes × n_nodes)

TruncatedSVD(n_components=32) 적용

각 컴퓨터 노드에 32차원 latent vector 부여

노드 이상 점수

임베딩 공간에서 GaussianMixture(n_components=4) 학습

음수 로그 likelihood -log p(x)를 이상 점수로 사용

점수가 클수록 “해당 컴퓨터가 다른 노드들과 다른 위치에 있음”이라는 의미

사용자 이상 점수

사용자별 집계 특징:

total_events

success_ratio, fail_ratio

unique_dst_computers

night_ratio (0~6, 20~24 시 활동 비율)

self_user_ratio (srcUser == dstUser 비율)

IsolationForest 학습 후 decision_function 기반 이상도 산출

각 특징의 z-score 절댓값을 “간단한 SHAP-like 기여도”로 저장

5.2 베이스라인 구간 결과 (공격 없는 정상 패턴)

윈도우

time ∈ [0, 43,200)

redteam 이벤트 0건

결과 해석

사용자·컴퓨터별 이상 점수 분포가 어떻게 생겼는지 확인하는 용도

이후 공격 구간과의 상대 비교 기준

이미지 삽입 위치 예시

![Baseline 사용자 이상도 랭크 곡선](baseline/user_if_curve.png)


해석 포인트

x축: 사용자 랭크(1이 가장 이상도가 높은 계정)

y축: IsolationForest 이상 점수

꼬리가 길게 늘어지고 일부 계정에서 급격히 상승하는 패턴

베이스라인에서도 이상도가 높은 계정 존재

비정상이라기보다 관리자 계정, 서비스 계정 등 활동량이 크거나 패턴이 특이한 계정일 가능성

![Baseline 컴퓨터 이상도 랭크 곡선](baseline/gmm_curve.png)


해석 포인트

x축: 컴퓨터 랭크

y축: GMM 기반 이상 점수

소수의 컴퓨터에서 점수가 크게 튀어 오르는 형태

이후 공격 구간에서 redteam 관련 컴퓨터가 이 상위구간에 얼마나 섞이는지 비교

![Baseline 사용자 특징 중요도](baseline/user_feature_importance.png)


해석 포인트

IsolationForest 전역 feature_importance

예시: total_events, unique_dst_computers, night_ratio 순으로 중요도가 높게 나오는 패턴

논문에서는

“야간 활동 비율”

“접속 대상 컴퓨터 다양도”

“전체 이벤트 수”
가 이상 탐지에 중요한 축이라는 근거로 활용 가능

5.3 공격 구간 예시 결과 (SVD 실험)

윈도우 설정

time ∈ [1,058,085, 1,101,285)

redteam 이벤트 포함

데이터 규모

이벤트 수: 약 1.4M

컴퓨터 노드 수: 10,163

사용자 수: 23,354

redteam 관련 개수

redteam 사용자 수: 39

redteam 컴퓨터 수: 92

모델 성능 (Top-100 기준)

사용자

Top-100 안에 포함된 redteam 사용자 수: 1

사용자 recall@100 ≒ 2.6%

무작위 선택 시 기대 적중 수:

100 × (39 / 23,354) ≒ 0.17

의미

무작위보다 약 15배 이상 높은 집중도

컴퓨터

Top-100 안에 포함된 redteam 컴퓨터 수: 6

컴퓨터 recall@100 ≒ 6.5%

무작위 선택 시 기대 적중 수:

100 × (92 / 10,163) ≒ 0.90

의미

무작위보다 약 7배 정도 높은 집중도

이미지 삽입 예시

![SVD 공격 구간 사용자 이상도 랭크 곡선](attack_1058085_1101285/user_if_curve.png)


해석 포인트

베이스라인 대비 상위 구간 기울기 변화 여부

공격 구간에서 상위 몇 개 계정의 이상도가 더 가파르게 상승하는 경향

redteam 계정이 이 상위 영역에 어느 정도 섞여 있는지 확인

![SVD 공격 구간 컴퓨터 이상도 랭크 곡선](attack_1058085_1101285/gmm_curve.png)


해석 포인트

공격 구간에서 특정 컴퓨터들의 이상 점수가 베이스라인보다 더 뾰족하게 튀는 패턴

redteam 관련 컴퓨터 중 일부가 상위 100위 안에 들어와 있음

![SVD 공격 구간 redteam 순위 분포 (사용자)](attack_1058085_1101285/redteam_rank_hist_user.png)
![SVD 공격 구간 redteam 순위 분포 (컴퓨터)](attack_1058085_1101285/redteam_rank_hist_computer.png)


해석 포인트

redteam 계정과 컴퓨터의 랭크 히스토그램

베이스라인에서는 redteam 자체가 없기 때문에 히스토그램이 존재하지 않음

공격 구간에서 redteam의 상당수가 전체 2~3만 개 중 상위 수천 등 이내에 집중되는지 확인 가능

논문에서는 “무작위 기준 대비 상위 랭크 집중도 상승”을 정량적으로 설명하는 근거로 사용

6. 실험 2: Node2Vec 기반 그래프 임베딩 + Isolation Forest

실험 2는 그래프 임베딩 부분만 Node2Vec으로 교체한 버전.
사용자 집계 특징과 Isolation Forest 파트는 실험 1과 동일 구조 유지.

6.1 Node2Vec 임베딩 개요

그래프 정의

동일하게 src_computer → dst_computer 성공 인증 그래프 사용

Node2Vec 설정 개요

차원 수: 32

walk 길이, walk 수, p, q 등은 노트북 환경에서 수 분 내 학습 가능하도록 설정

매 랜덤 워크로 컴퓨터 간 이동 패턴을 추출하고, Word2Vec 스타일 학습으로 노드 임베딩 생성

이후 파이프라인

임베딩 → GMM 기반 컴퓨터 이상 점수

사용자 집계 특징 → Isolation Forest

redteam에 대한 hit@100 계산 방식은 실험 1과 동일

6.2 공격 구간 예시 결과 (Node2Vec 실험)

윈도우 설정

time ∈ [1,166,400, 1,209,600)

redteam 이벤트 포함

데이터 규모

컴퓨터 노드 수: 11,414

사용자 수: 25,884

redteam 사용자 수: 14

redteam 컴퓨터 수: 37

모델 성능 (Top-100 기준)

사용자

Top-100 안에 포함된 redteam 사용자 수: 2

recall@100 ≒ 14.3%

무작위 선택 시 기대 적중 수:

100 × (14 / 25,884) ≒ 0.08

의미

무작위보다 약 175배 수준의 집중도 상승

컴퓨터

Top-100 안에 포함된 redteam 컴퓨터 수: 5

recall@100 ≒ 13.5%

무작위 선택 시 기대 적중 수:

100 × (37 / 11,414) ≒ 0.32

의미

무작위보다 약 15배 수준의 집중도 상승

이미지 삽입 예시

![Node2Vec 공격 구간 사용자 이상도 랭크 곡선](attack_1166400_1209600/user_if_curve.png)
![Node2Vec 공격 구간 컴퓨터 이상도 랭크 곡선](attack_1166400_1209600/gmm_curve.png)
![Node2Vec 공격 구간 redteam 순위 분포 (사용자)](attack_1166400_1209600/redteam_rank_hist_user.png)
![Node2Vec 공격 구간 redteam 순위 분포 (컴퓨터)](attack_1166400_1209600/redteam_rank_hist_computer.png)


해석 포인트

SVD보다 redteam 사용자와 컴퓨터가 상위 100위 안에 더 많이 포함

특히 사용자 측에서 무작위 대비 수십~수백 배 수준의 집중도

그래프 random walk 기반 임베딩이 정적 행렬 SVD보다 공격 시나리오의 접속 경로 패턴을 더 잘 잡아내는 경향

7. 두 실험 비교·해석 요약
7.1 성능 비교 (대표 윈도우 기준)
실험	윈도우 (초)	redteam 사용자 수	hit_user@100	사용자 recall@100	무작위 기대 hit	실험/무작위 비율
SVD	1,058,085 ~ 1,101,285	39	1	약 2.6%	약 0.17	약 15배
Node2Vec	1,166,400 ~ 1,209,600	14	2	약 14.3%	약 0.08	약 175배
실험	redteam 컴퓨터 수	hit_comp@100	컴퓨터 recall@100	무작위 기대 hit	실험/무작위 비율
SVD	92	6	약 6.5%	약 0.90	약 7배
Node2Vec	37	5	약 13.5%	약 0.32	약 15배
7.2 해석

SVD 실험

공격 구간에서 redteam 컴퓨터·사용자를 우연히 기대되는 수준보다 명확히 더 많이 상위 랭크로 올리는 결과

대수준 구조(주요 허브 컴퓨터, 초다수 이벤트 계정)를 잘 잡지만, 접속 경로의 세부 패턴까지는 제한적 포착

Node2Vec 실험

동일한 파이프라인에서 그래프 임베딩 부분만 교체했을 뿐인데,

redteam 사용자·컴퓨터에 대한 recall@100이 전반적으로 더 높게 나타나는 경향

특히 사용자 측에서 무작위 기대값 대비 큰 배수 차이

random walk 기반이라 공격 시나리오에서 나타나는 “연속 로그인/피벗 이동 패턴”을 더 잘 반영하는 것으로 해석 가능

7.3 논문 관점에서의 활용 방안

공통 메시지

LANL 대규모 인증 로그에서, 완전 비지도 세팅으로도 redteam 공격 구간에서

사용자·컴퓨터 이상 점수가 무작위 대비 명확히 높은 집중도를 보임

이는 “사용자–컴퓨터 관계 그래프 기반 UEBA 접근이 실질적인 공격 탐지 가능성을 가진다”는 실험적 근거 역할

실험 선택 제안

논문 본문에 메인 결과로 소개

Node2Vec 기반 실험 (실험 2)

부록 또는 ablation으로 소개

SVD 기반 latent position 실험 (실험 1)

“행렬 분해 기반 단순 임베딩 대비 random-walk 기반 임베딩이 redteam 집중도 측면에서 더 유리”라는 비교 결과 제시

8. 레포지토리 구조 템플릿

실제 GitHub 레포는 대략 다음 구조로 정리 가능.

.
├─ README.md                        # 본 문서
├─ experiment_svd.py                # 실험 1: SVD 기반 파이프라인
├─ experiment_node2vec.py           # 실험 2: Node2Vec 기반 파이프라인
├─ config_example.py                
├─ results_svd/
│   ├─ baseline/
│   │   ├─ metrics.json
│   │   ├─ user_if_curve.png
│   │   ├─ gmm_curve.png
│   │   └─ user_feature_importance.png
│   └─ attack_1058085_1101285/
│       ├─ metrics.json
│       ├─ computer_scores.csv
│       ├─ user_scores.csv
│       ├─ user_feature_contrib.csv
│       ├─ user_if_curve.png
│       ├─ gmm_curve.png
│       ├─ redteam_rank_hist_user.png
│       └─ redteam_rank_hist_computer.png
└─ results_node2vec/
    ├─ baseline/
    │   ├─ metrics.json
    │   ├─ user_if_curve.png
    │   └─ gmm_curve.png
    └─ attack_1166400_1209600/
        ├─ metrics.json
        ├─ computer_scores.csv
        ├─ user_scores.csv
        ├─ user_feature_contrib.csv
        ├─ user_if_curve.png
        ├─ gmm_curve.png
        ├─ redteam_rank_hist_user.png
        └─ redteam_rank_hist_computer.png
