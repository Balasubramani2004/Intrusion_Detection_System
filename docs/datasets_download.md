# Dataset Download Guide (N5 — Modern IoT Evaluation)

FedAIDA-IDS ships with **NSL-KDD** for first training. **Bot-IoT** and **CICIDS2018** are required for paper-grade N5 results (Macro F1 > 0.94 on Bot-IoT).

## Current status

| Dataset | Folder | Minimum for smoke train | Full paper eval |
|---------|--------|-------------------------|-----------------|
| NSL-KDD | `datasets/nsl_kdd/` | `KDDTrain+.txt`, `KDDTest+.txt` | Same (already included) |
| Bot-IoT | `datasets/bot_iot/` | 5% sample CSVs (included) | Full feature CSV set (~1.2 GB+) |
| CICIDS2018 | `datasets/cicids2018/` | One day CSV (optional) | All day CSVs from CIC |

## NSL-KDD (required)

1. https://www.unb.ca/cic/datasets/nsl.html
2. Download `KDDTrain+.txt` and `KDDTest+.txt`
3. Place in `datasets/nsl_kdd/`

## Bot-IoT (full — manual download)

1. https://research.unsw.edu.au/projects/bot-iot-dataset
2. Download **Feature extraction CSVs** (not raw PCAP for training)
3. Extract all `*.csv` into `datasets/bot_iot/`
4. Verify:

```bash
ls datasets/bot_iot/*.csv | wc -l   # expect multiple large files
python3 -c "from data.preprocess import load_bot_iot; print('rows', len(load_bot_iot()))"
```

## CSE-CIC-IDS2018 (full — manual download)

1. https://www.unb.ca/cic/datasets/ids-2018.html
2. Register and download **CSV files** (or PCAP + use project extractor)
3. Place CSVs in `datasets/cicids2018/`
4. If only PCAP available, place under `datasets/cicids2018/` — preprocessing can extract flows to `datasets/cicids2018/extracted_csv/`

## Verify after download

```bash
cd fedaida_ids
source .venv/bin/activate
python3 -m pytest tests/test_preprocess.py -q
python3 train.py --dataset bot_iot --rounds 1 --nodes 3   # smoke
```

## Notes

- Full Bot-IoT + CICIDS2018 exceed Git LFS limits — **do not commit** to git; keep local or use cloud storage.
- Sample Bot-IoT files (`Full5pc_*`) are enough for pipeline smoke tests only, not paper F1 targets.
