import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATHS = {
    "nsl_kdd": {
        "train": os.path.join(BASE_DIR, "datasets/nsl_kdd/KDDTrain+.txt"),
        "test":  os.path.join(BASE_DIR, "datasets/nsl_kdd/KDDTest+.txt"),
    },
    "cicids":   {"dir": os.path.join(BASE_DIR, "datasets/cicids2018/")},
    "bot_iot":  {"dir": os.path.join(BASE_DIR, "datasets/bot_iot/")},
}
RESULTS_DIR  = os.path.join(BASE_DIR, "results")
PLOTS_DIR    = os.path.join(BASE_DIR, "results/plots")
METRICS_DIR  = os.path.join(BASE_DIR, "results/metrics")
MODELS_DIR   = os.path.join(BASE_DIR, "saved_models")
MODEL_DIR    = MODELS_DIR  # dashboard alias
LOGS_DIR     = os.path.join(BASE_DIR, "logs")
DATASET      = "nsl_kdd"
NUM_FEATURES = 41
NUM_CLASSES  = 5
SEQUENCE_LEN = 10
TEST_SIZE    = 0.15
VAL_SIZE     = 0.15
RANDOM_SEED  = 42
NUM_NODES    = 9
FL_ROUNDS    = 50
LOCAL_EPOCHS = 5
MIN_FIT_CLIENTS  = 6
MIN_EVAL_CLIENTS = 4
FRACTION_FIT = 0.8
IRBA_COSINE_WEIGHT   = 0.4
IRBA_COVERAGE_WEIGHT = 0.4
IRBA_HISTORY_WEIGHT  = 0.2
IRBA_QUARANTINE_THRESH = 0.20
IRBA_NEW_NODE_TRUST  = 0.50
IRBA_MAX_TRUST       = 0.95
NUM_BYZANTINE_NODES  = 2
ADWIN_DELTA          = 0.002
DRIFT_CHECK_INTERVAL = 50
DRIFT_FL_ROUNDS      = 3
CNN_FILTERS     = 64
CNN_KERNEL      = 3
LSTM_UNITS      = 128
ATTENTION_UNITS = 64
ANFIS_RULES     = 20
DROPOUT_RATE    = 0.3
L2_REG          = 1e-4
BATCH_SIZE      = 64
LEARNING_RATE   = 0.001
MAX_EPOCHS      = 50
EARLY_STOPPING  = 10
NUM_SEEDS         = 5
DASHBOARD_HOST    = "0.0.0.0"
DASHBOARD_PORT    = 5000
DASHBOARD_DEBUG   = False
CONFIDENCE_HIGH   = 0.90
CONFIDENCE_MEDIUM = 0.70
ALERT_CONFIDENCE_THRESHOLD = CONFIDENCE_MEDIUM
MIN_FLOW_PACKETS = 3
# LAN Wi-Fi: detect nmap/port-scan from ANY device on the network we can see
LAN_SCAN_ENABLED = True
SCAN_WINDOW_SEC = 30
SCAN_MIN_UNIQUE_PORTS = 10
SCAN_MIN_SYN_EVENTS = 8
SCAN_BURST_WINDOW_SEC = 12
SCAN_BURST_MIN_PORTS = 8
SCAN_BURST_MIN_SYN_EVENTS = 8
SCAN_LOCAL_BURST_MIN_PORTS = 6
SCAN_ALERT_COOLDOWN_SEC = 40
SCAN_HEURISTIC_THRESHOLD = 0.78
SCAN_EXCLUDE_PORTS = frozenset({53, 80, 443, 8080, 8443, 993, 587, 22, 8000, 8888})
LAN_ARP_SWEEP_ENABLED = False
LAN_ARP_WINDOW_SEC = 25
LAN_ARP_MIN_HOSTS = 8
LAN_ARP_COOLDOWN_SEC = 60
# Extra laptop LAN IP(s) if auto-detect misses (college DHCP changes daily).
# Leave empty when using WSL — Windows Wi-Fi IP is detected at dashboard start.
# Or before each session: export DASHBOARD_LOCAL_IPS=10.10.x.x
LOCAL_IP_WHITELIST = []
DONT_AUTO_BLOCK_LOCAL_IPS = True
# Wi-Fi demo: only alert when YOUR laptop is the scan target (victim), not when
# you appear as "scanner" due to normal outbound TCP (browser, chat, etc.).
LAN_SCAN_VICTIM_ALERT_ONLY = True
# Live Wi-Fi: strict = port-scan rules only (no noisy ML DoS/R2L)
LIVE_ALERT_MODE = "strict"
LIVE_ML_ALERT_CONFIDENCE = 0.88
PROBE_CLASS_ID = 2
TSHARK_INCOMING_DIR = os.path.join(BASE_DIR, "capture", "incoming")
TSHARK_PROCESSED_DIR = os.path.join(BASE_DIR, "capture", "processed")
ATTACK_NAMES      = {
    0: 'Normal',
    1: 'DoS',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R',
}
CICIDS_ATTACK_NAMES = {
    0: 'Benign',
    1: 'DoS/DDoS',
    2: 'PortScan',
    3: 'BruteForce',
    4: 'Infiltration',
}
BOTIOT_ATTACK_NAMES = {
    0: 'Normal',
    1: 'DDoS',
    2: 'DoS',
    3: 'Reconnaissance',
    4: 'Theft',
}
NSL_KDD_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate','label','difficulty']
NSL_KDD_LABEL_MAP = {
    'normal':0,'neptune':1,'back':1,'land':1,'pod':1,'smurf':1,'teardrop':1,
    'apache2':1,'udpstorm':1,'processtable':1,'worm':1,
    'satan':2,'ipsweep':2,'nmap':2,'portsweep':2,'mscan':2,'saint':2,
    'guess_passwd':3,'ftp_write':3,'imap':3,'phf':3,'multihop':3,
    'warezmaster':3,'warezclient':3,'spy':3,'xlock':3,'xsnoop':3,
    'snmpguess':3,'snmpgetattack':3,'httptunnel':3,'sendmail':3,'named':3,
    'buffer_overflow':4,'loadmodule':4,'rootkit':4,'perl':4,'sqlattack':4,
    'xterm':4,'ps':4}
NSL_KDD_LABEL_NAMES = ['Normal','DoS','Probe','R2L','U2R']
CATEGORICAL_COLS = ['protocol_type','service','flag']
