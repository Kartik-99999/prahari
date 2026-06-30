# Data

This directory is **gitignored** (except `README.md` and `threat_intel/*.md`).
Generated artifacts (`events.jsonl`, `ground_truth.json`, `ueba_*.csv`,
`incidents.json`, `metrics_slate.json`, …) are reproduced by the pipeline; large
datasets are fetched on demand and never committed.

## Synthetic scenarios (no download)

- Scenario 1 (State Examinations Authority APT): `make generate` /
  `make graph-load` regenerate `events.jsonl` + `ground_truth.json` (seed 42).
- Scenario 2 (generalization, frozen thresholds): `make scenario2`.

## Public benchmark — CIC-IDS-2017  [G1]

`make ueba-benchmark` expects the *MachineLearningCVE* per-day flow CSVs under
`data/benchmark/cicids2017/`. The canonical CIC distribution
(`cicresearch.ca` / `unb.ca/cic/datasets/ids-2017`) is **registration-gated**
(it redirects to an HTML landing page), so we fetch the identical CSVs from the
public Hugging Face mirror `c01dsnap/CIC-IDS2017`:

```bash
mkdir -p data/benchmark/cicids2017
base="https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main"
curl -L -o data/benchmark/cicids2017/Friday-PortScan.csv \
  "$base/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv?download=true"
curl -L -o data/benchmark/cicids2017/Friday-DDoS.csv \
  "$base/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv?download=true"
# (optional, larger) other days: Wednesday-workingHours / Tuesday-WorkingHours / Thursday-*
```

Files used (manageable subset): `Friday-PortScan.csv` (286,467 rows;
PortScan 158,930 / BENIGN 127,537) and `Friday-DDoS.csv` (225,745 rows;
DDoS 128,027 / BENIGN 97,718). Pure numeric CICFlowMeter features + `Label`.

If the mirror is unavailable, the documented fallback is **UNSW-NB15**
(`UNSW_NB15_training-set.csv` / `_testing-set.csv`); point `benchmark.py` at the
CSVs with the same Label→binary preprocessing.

## ATT&CK knowledge base

`make attack-kb` fetches the live MITRE ATT&CK Enterprise STIX bundle to
`data/attack/enterprise-attack.json` (falls back to `packages/attack_subset.json`).
