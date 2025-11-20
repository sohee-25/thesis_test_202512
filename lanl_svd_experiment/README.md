
# LANL Experiment Result

- Baseline window: 0 ~ 43200
- Attack windows: [(np.int64(150885), np.int64(194085)), (np.int64(194085), np.int64(237285)), (np.int64(453285), np.int64(496485)), (np.int64(539685), np.int64(582885)), (np.int64(582885), np.int64(626085)), (np.int64(626085), np.int64(669285)), (np.int64(712485), np.int64(755685)), (np.int64(755685), np.int64(798885)), (np.int64(798885), np.int64(842085)), (np.int64(1058085), np.int64(1101285)), (np.int64(1101285), np.int64(1144485)), (np.int64(1144485), np.int64(1187685)), (np.int64(1230885), np.int64(1274085)), (np.int64(1317285), np.int64(1360485)), (np.int64(1360485), np.int64(1403685)), (np.int64(1749285), np.int64(1792485)), (np.int64(1835685), np.int64(1878885)), (np.int64(1922085), np.int64(1965285)), (np.int64(2267685), np.int64(2310885)), (np.int64(2354085), np.int64(2397285)), (np.int64(2440485), np.int64(2483685)), (np.int64(2526885), np.int64(2570085))]

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
