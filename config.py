import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATHS = {
    "nsl_kdd": {
        "train": os.path.join(BASE_DIR, "datasets/nsl_kdd/KDDTrain+.txt"),
        "test":  os.path.join(BASE_DIR, "datasets/nsl_kdd/KDDTest+.txt"),
    },
    "cicids":   {"dir": os.path.join(BASE_DIR, "datasets/cicids2017/")},
    "bot_iot":  {"dir": os.path.join(BASE_DIR, "datasets/bot_iot/")},
}
RESULTS_DIR  = os.path.join(BASE_DIR, "results")
PLOTS_DIR    = os.path.join(BASE_DIR, "results/plots")
METRICS_DIR  = os.path.join(BASE_DIR, "results/metrics")
MODELS_DIR   = os.path.join(BASE_DIR, "saved_models")
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
CNN_KERNEL_SIZE = 3
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
NUM_CLASSES       = 5
DASHBOARD_HOST    = "0.0.0.0"
DASHBOARD_PORT    = 5000
DASHBOARD_DEBUG   = False
MODEL_DIR         = os.path.join(BASE_DIR, "saved_models")  # alias for MODELS_DIR
CONFIDENCE_HIGH   = 0.90
CONFIDENCE_MEDIUM = 0.70
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
