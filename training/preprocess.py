import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import json
import os

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]


PROTOCOL_MAP = {"tcp": 0, "udp": 1, "icmp": 2}

SERVICE_MAP = {
    "http": 0, "ftp": 1, "smtp": 2, "ssh": 3, "dns": 4,
    "ftp_data": 5, "mtp": 6, "finger": 7, "telnet": 8, "eco_i": 9,
    "other": 10, "private": 11, "domain_u": 12, "auth": 13, "ntp_u": 14,
    "http_443": 15, "Z39_50": 16, "ldap": 17, "klogin": 18, "kshell": 19,
    "imap4": 20, "pop_3": 21, "pop_2": 22, "systat": 23, "sunrpc": 24,
    "gopher": 25, "uucp": 26, "netstat": 27, "nntp": 28, "whois": 29,
    "shell": 30, "courier": 31, "csnet_ns": 32, "ctf": 33, "daytime": 34,
    "discard": 35, "domain": 36, "echo": 37, "efs": 38, "exec": 39,
    "hostnames": 40, "http_2784": 41, "http_8001": 42, "iso_tsap": 43,
    "link": 44, "login": 45, "name": 46, "netbios_dgm": 47,
    "netbios_ns": 48, "netbios_ssn": 49, "nnsp": 50, "pm_dump": 51,
    "printer": 52, "remote_job": 53, "rje": 54, "sql_net": 55,
    "supdup": 56, "time": 57, "tim_i": 58, "urh_i": 59, "urp_i": 60,
    "uucp_path": 61, "vmnet": 62, "X11": 63, "IRC": 64, "harvest": 65,
    "aol": 66, "red_i": 67, "tftp_u": 68, "icmp": 69,
}

FLAG_MAP = {
    "SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTS": 4,
    "SH": 5, "S1": 6, "S2": 7, "S3": 8, "OTH": 9,
}

LABEL_MAP = {
    "normal": 0,
    "back": 1, "land": 1, "neptune": 1, "pod": 1, "smurf": 1,
    "teardrop": 1, "apache2": 1, "udpstorm": 1, "processtable": 1,
    "worm": 1, "mailbomb": 1,
    "satan": 2, "ipsweep": 2, "nmap": 2, "portsweep": 2, "mscan": 2,
    "saint": 2,
    "guess_passwd": 3, "ftp_write": 3, "imap": 3, "phf": 3, "multihop": 3,
    "warezmaster": 3, "warezclient": 3, "spy": 3, "xlock": 3,
    "xsnoop": 3, "snmpgetattack": 3, "named": 3, "sendmail": 3,
    "httptunnel": 3, "snmpguess": 3, "rusersd": 3, "rsh": 3,
    "sqlattack": 3, "xterm": 3,
    "buffer_overflow": 4, "loadmodule": 4, "rootkit": 4, "perl": 4,
    "ps": 4, "httptunnel": 4,
}


def load_dataset(path):
    """Load one NSL-KDD file and return a cleaned DataFrame."""
    df = pd.read_csv(path, header=None, names=COLUMNS)

    df = df.drop(columns=["difficulty"])

    return df


def encode_features(df):
    """
    Apply encoding maps to the three categorical columns.
    .map() applies the dictionary as a lookup table to every row.
    Unknown values become NaN; .fillna(0) replaces those with 0 (our default).
    This mirrors the Go extractor's behaviour of defaulting unknowns to 0.
    """
    df = df.copy()
    df["protocol_type"] = df["protocol_type"].map(PROTOCOL_MAP).fillna(0)
    df["service"]       = df["service"].map(SERVICE_MAP).fillna(0)
    df["flag"]          = df["flag"].map(FLAG_MAP).fillna(0)
    return df


def encode_labels(df):
    """Collapse specific attack names into the five class indices."""
    labels = df["label"].str.strip().str.lower().map(LABEL_MAP)

    labels = labels.fillna(0).astype(int)
    return labels


def preprocess(train_path="KDDTrain+.txt", test_path="KDDTest+.txt"):
    print("Loading datasets...")
    train_df = load_dataset(train_path)
    test_df  = load_dataset(test_path)

    print("Encoding categorical features...")
    train_df = encode_features(train_df)
    test_df  = encode_features(test_df)

    feature_cols = [c for c in train_df.columns if c != "label"]
    X_train = train_df[feature_cols].values.astype(np.float32)
    y_train = encode_labels(train_df).values

    X_test  = test_df[feature_cols].values.astype(np.float32)
    y_test  = encode_labels(test_df).values

    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    print("Fitting scaler on training data...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    os.makedirs("../models", exist_ok=True)
    scaler_params = {
        "mean":  scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
    }
    with open("../models/scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=2)
    print("Saved scaler_params.json")

    return X_train_scaled, y_train, X_test_scaled, y_test, scaler


if __name__ == "__main__":
    preprocess()
    print("Preprocessing complete.")