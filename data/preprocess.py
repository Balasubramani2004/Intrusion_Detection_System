"""
FedAIDA-IDS — Data Preprocessing
Handles NSL-KDD, CICIDS2017, Bot-IoT
"""
import os, glob, pickle, logging
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _maybe_extract_flows_from_pcaps(data_dir: str) -> None:
    """
    If the dataset directory contains PCAP/PCAPNG files but no CSVs,
    attempt to generate flow-feature CSVs using `data.pcap_to_flow`.
    """
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    if csv_files:
        return
    pcap_files = glob.glob(os.path.join(data_dir, "*.pcap")) + glob.glob(os.path.join(data_dir, "*.pcapng"))
    if not pcap_files:
        return
    try:
        from data.pcap_to_flow import extract_directory
        out_dir = os.path.join(data_dir, "extracted_csv")
        logger.info(f"No CSVs found; extracting flows from PCAPs → {out_dir}")
        res = extract_directory(data_dir, out_dir, backend="auto")
        logger.info(f"Flow extraction backend={res.backend}, csv_count={len(res.outputs)}")
    except Exception as e:
        logger.warning(
            "PCAPs found but flow extraction failed. "
            "Either install `cicflowmeter` CLI or set CICFLOWMETER_JAR.\n"
            f"Error: {e}"
        )


# ── NSL-KDD ──────────────────────────────────────────────────
def load_nslkdd(train_path, test_path, label_map, cols, cat_cols):
    logger.info("Loading NSL-KDD dataset...")
    df_tr = pd.read_csv(train_path, names=cols, header=None)
    df_te = pd.read_csv(test_path,  names=cols, header=None)

    for df in [df_tr, df_te]:
        df['label'] = df['label'].str.strip().str.lower().map(label_map).fillna(0).astype(int)
        df.drop(columns=['difficulty'], inplace=True, errors='ignore')

    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        le.fit(pd.concat([df_tr[col], df_te[col]]))
        df_tr[col] = le.transform(df_tr[col])
        df_te[col] = le.transform(df_te[col])
        encoders[col] = le

    feat_cols = [c for c in df_tr.columns if c != 'label']
    X_tr = df_tr[feat_cols].values.astype(np.float32)
    y_tr = df_tr['label'].values
    X_te = df_te[feat_cols].values.astype(np.float32)
    y_te = df_te['label'].values

    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_tr)
    X_te = scaler.transform(X_te)

    logger.info(f"  Train: {X_tr.shape} | Test: {X_te.shape}")
    return X_tr, y_tr, X_te, y_te, scaler, encoders


# ── CICIDS ───────────────────────────────────────────────────
CICIDS_LABEL_MAP = {
    'BENIGN': 0, 'DoS Hulk': 1, 'PortScan': 2, 'DDoS': 1,
    'DoS GoldenEye': 1, 'FTP-Patator': 3, 'SSH-Patator': 3,
    'DoS slowloris': 1, 'DoS Slowhttptest': 1, 'Bot': 4,
    'Web Attack \x96 Brute Force': 3, 'Web Attack – Brute Force': 3,
    'Web Attack \x96 XSS': 3, 'Web Attack – XSS': 3,
    'Infiltration': 4, 'Web Attack \x96 Sql Injection': 3,
    'Web Attack – Sql Injection': 3, 'Heartbleed': 4,
}
CICIDS_LABEL_NAMES = ['Benign', 'DoS/DDoS', 'PortScan', 'BruteForce', 'Infiltration']

def load_cicids(data_dir):
    logger.info("Loading CICIDS2017 dataset...")
    _maybe_extract_flows_from_pcaps(data_dir)
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not csv_files:
        # allow extracted subdir convention
        csv_files = glob.glob(os.path.join(data_dir, "extracted_csv", "*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files in {data_dir}")

    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
            logger.info(f"  {os.path.basename(f)}: {df.shape}")
        except Exception as e:
            logger.warning(f"  Skipping {f}: {e}")

    df = pd.concat(dfs, ignore_index=True)
    label_col = 'Label' if 'Label' in df.columns else ' Label'
    df['label'] = df[label_col].str.strip().map(CICIDS_LABEL_MAP).fillna(0).astype(int)
    df.drop(columns=[label_col], inplace=True, errors='ignore')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    feat_cols = [c for c in df.columns if c != 'label']
    X = df[feat_cols].values.astype(np.float32)
    y = df['label'].values

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_tr)
    X_te = scaler.transform(X_te)

    logger.info(f"  Train: {X_tr.shape} | Test: {X_te.shape}")
    return X_tr, y_tr, X_te, y_te, scaler, feat_cols


# ── BOT-IOT ──────────────────────────────────────────────────
BOTIOT_LABEL_NAMES = ['Normal', 'DDoS', 'DoS', 'Reconnaissance', 'Theft']

def load_botiot(data_dir):
    logger.info("Loading Bot-IoT dataset...")
    _maybe_extract_flows_from_pcaps(data_dir)
    csv_files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))[:5]
    if not csv_files:
        csv_files = sorted(glob.glob(os.path.join(data_dir, "extracted_csv", "*.csv")))[:5]
    if not csv_files:
        raise FileNotFoundError(f"No CSV files in {data_dir}")

    dfs = [pd.read_csv(f, low_memory=False) for f in csv_files]
    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.strip().str.lower()

    label_map = {'normal': 0, 'ddos': 1, 'dos': 2, 'reconnaissance': 3, 'theft': 4}
    lbl_col = 'category' if 'category' in df.columns else df.columns[-1]
    df['label'] = df[lbl_col].astype(str).str.strip().str.lower().map(label_map).fillna(0).astype(int)

    drop_cols = [c for c in df.columns if df[c].dtype == object or c == lbl_col]
    df.drop(columns=drop_cols, inplace=True, errors='ignore')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    feat_cols = [c for c in df.columns if c != 'label']
    X = df[feat_cols].values.astype(np.float32)
    y = df['label'].values

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_tr)
    X_te = scaler.transform(X_te)

    logger.info(f"  Train: {X_tr.shape} | Test: {X_te.shape}")
    return X_tr, y_tr, X_te, y_te, scaler, feat_cols


# ── SMOTE ────────────────────────────────────────────────────
def apply_smote(X, y, random_state=42):
    logger.info("Applying SMOTE class balancing...")
    unique, counts = np.unique(y, return_counts=True)
    logger.info(f"  Before: {dict(zip(unique.tolist(), counts.tolist()))}")
    min_count = int(min(counts))
    if min_count < 6:
        logger.warning("  Classes too rare for SMOTE, skipping")
        return X, y
    k = min(5, min_count - 1)
    sm = SMOTE(random_state=random_state, k_neighbors=k)
    X_res, y_res = sm.fit_resample(X, y)
    unique2, counts2 = np.unique(y_res, return_counts=True)
    logger.info(f"  After:  {dict(zip(unique2.tolist(), counts2.tolist()))}")
    return X_res, y_res


# ── NON-IID PARTITION ────────────────────────────────────────
def partition_non_iid(X, y, n_nodes, num_classes, seed=42):
    """Dirichlet-based Non-IID partition across FL nodes."""
    np.random.seed(seed)
    node_X = [[] for _ in range(n_nodes)]
    node_y = [[] for _ in range(n_nodes)]
    alpha = 0.5

    for c in range(num_classes):
        idx = np.where(y == c)[0]
        if len(idx) == 0:
            continue
        np.random.shuffle(idx)
        props = np.random.dirichlet(np.repeat(alpha, n_nodes))
        props = (props * len(idx)).astype(int)
        props[-1] = len(idx) - props[:-1].sum()
        start = 0
        for nid, cnt in enumerate(props):
            end = start + max(cnt, 0)
            node_X[nid].append(X[idx[start:end]])
            node_y[nid].append(y[idx[start:end]])
            start = end

    partitions = []
    for i in range(n_nodes):
        if node_X[i] and any(len(x) > 0 for x in node_X[i]):
            Xi = np.vstack([x for x in node_X[i] if len(x) > 0])
            yi = np.hstack([l for l in node_y[i] if len(l) > 0])
            perm = np.random.permutation(len(yi))
            partitions.append((Xi[perm], yi[perm]))
            logger.info(f"  Node {i+1:2d}: {len(yi):6d} samples | "
                        f"classes: {np.unique(yi, return_counts=True)[1].tolist()}")
        else:
            partitions.append((np.zeros((1, X.shape[1])), np.zeros(1, dtype=int)))

    return partitions


# ── SEQUENCES ────────────────────────────────────────────────
def create_sequences(X, y, seq_len):
    """Sliding window: convert flows to BiLSTM-compatible sequences."""
    if len(X) < seq_len:
        return np.empty((0, seq_len, X.shape[1]), dtype=np.float32), np.empty(0, dtype=np.int32)
    Xs, ys = [], []
    for i in range(len(X) - seq_len + 1):
        Xs.append(X[i:i + seq_len])
        ys.append(y[i + seq_len - 1])
    return np.array(Xs, dtype=np.float32), np.array(ys, dtype=np.int32)


# ── MASTER LOAD ──────────────────────────────────────────────
def prepare_all(dataset_name, cfg):
    """Load, clean, balance, partition, and create sequences."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import (DATASET_PATHS, NSL_KDD_COLS, NSL_KDD_LABEL_MAP,
                        CATEGORICAL_COLS, NUM_NODES, NUM_CLASSES,
                        SEQUENCE_LEN, MODELS_DIR)

    if dataset_name == 'nsl_kdd':
        X_tr, y_tr, X_te, y_te, scaler, _ = load_nslkdd(
            DATASET_PATHS['nsl_kdd']['train'], DATASET_PATHS['nsl_kdd']['test'],
            NSL_KDD_LABEL_MAP, NSL_KDD_COLS, CATEGORICAL_COLS)
        label_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
        n_classes = 5

    elif dataset_name == 'cicids':
        X_tr, y_tr, X_te, y_te, scaler, _ = load_cicids(DATASET_PATHS['cicids']['dir'])
        label_names = CICIDS_LABEL_NAMES
        n_classes = 5

    elif dataset_name == 'bot_iot':
        X_tr, y_tr, X_te, y_te, scaler, _ = load_botiot(DATASET_PATHS['bot_iot']['dir'])
        label_names = BOTIOT_LABEL_NAMES
        n_classes = 5

    else:
        raise ValueError(f"Unknown dataset: {dataset_name}")

    # Balance
    X_tr, y_tr = apply_smote(X_tr, y_tr)

    # Partition for federation
    partitions = partition_non_iid(X_tr, y_tr, NUM_NODES, n_classes)

    # Create sequences
    X_te_seq, y_te_seq = create_sequences(X_te, y_te, SEQUENCE_LEN)
    node_seqs = []
    for Xn, yn in partitions:
        Xs, ys = create_sequences(Xn, yn, SEQUENCE_LEN)
        node_seqs.append((Xs, ys))

    # Save scaler
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(os.path.join(MODELS_DIR, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)

    n_features = X_tr.shape[1]
    logger.info(f"\nDataset ready | features={n_features} | "
                f"nodes={len(node_seqs)} | test_seq={X_te_seq.shape}")

    return node_seqs, (X_te_seq, y_te_seq), label_names, scaler, n_features
