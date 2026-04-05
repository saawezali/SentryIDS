import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import json

COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

PROTOCOL_MAP = {'tcp': 0, 'udp': 1, 'icmp': 2}
FLAG_MAP = {'SF':0,'S0':1,'REJ':2,'RSTO':3,'RSTS':4,'SH':5,'S1':6,'S2':7,'S3':8,'OTH':9}

SERVICE_MAP = {
    'http':0,'ftp':1,'smtp':2,'ssh':3,'dns':4,'ftp_data':5,'telnet':6,
    'finger':7,'domain_u':8,'auth':9,'login':10,'other':11,'private':12,
    'eco_i':13,'time':14,'ecr_i':15,'urp_i':16,'red_i':17,'IRC':18,
    'X11':19,'Z39_50':20,'urh_i':21,'http_443':22,'nntp':23,'gopher':24,
    'uucp':25,'name':26,'netbios_ns':27,'netbios_ssn':28,'netbios_dgm':29,
    'sql_net':30,'vmnet':31,'bgp':32,'supdup':33,'uucp_path':34,'nnsp':35,
    'http_8001':36,'http_2784':37,'aol':38,'harvest':39,'csnet_ns':40,
    'pop_3':41,'pop_2':42,'systat':43,'sunrpc':44,'kshell':45,'imap4':46,
    'efs':47,'whois':48,'netstat':49,'link':50,'remote_job':51,'ctf':52,
    'discard':53,'mtp':54,'echo':55,'shell':56,'daytime':57,'iso_tsap':58,
    'tim_i':59,'pm_dump':60,'rje':61,'printer':62,'courier':63,'exec':64,
    'ldap':65,'hostnames':66,'domain':67,'klogin':68,'ntp_u':69
}

LABEL_MAP = {
    'normal': 0,
    'back':1,'land':1,'neptune':1,'pod':1,'smurf':1,'teardrop':1,
    'apache2':1,'udpstorm':1,'processtable':1,'worm':1,'mailbomb':1,
    'ipsweep':2,'nmap':2,'portsweep':2,'satan':2,'mscan':2,'saint':2,
    'ftp_write':3,'guess_passwd':3,'imap':3,'multihop':3,'phf':3,
    'spy':3,'warezclient':3,'warezmaster':3,'snmpguess':3,'xlock':3,
    'xsnoop':3,'sendmail':3,'named':3,'httptunnel':3,'snmpgetattack':3,
    'buffer_overflow':4,'loadmodule':4,'perl':4,'rootkit':4,
    'sqlattack':4,'xterm':4,'ps':4,
}

def load_and_preprocess(path, scaler=None, fit_scaler=False):
    df = pd.read_csv(path, names=COLUMNS, header=None)
    df = df.drop('difficulty', axis=1)

    df['protocol_type'] = df['protocol_type'].map(PROTOCOL_MAP).fillna(0)
    df['service'] = df['service'].map(SERVICE_MAP).fillna(11)
    df['flag'] = df['flag'].map(FLAG_MAP).fillna(9)

    df['label'] = df['label'].str.lower().map(LABEL_MAP).fillna(0).astype(int)

    X = df.drop('label', axis=1).values.astype(np.float32)
    y = df['label'].values

    if fit_scaler:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
        return X, y, scaler
    elif scaler is not None:
        X = scaler.transform(X)
        return X, y, scaler
    return X, y, None

if __name__ == '__main__':
    print("Loading training data...")
    X_train, y_train, scaler = load_and_preprocess('data/KDDTrain+.txt', fit_scaler=True)
    X_test, y_test, _ = load_and_preprocess('data/KDDTest+.txt', scaler=scaler)

    np.save('data/X_train.npy', X_train)
    np.save('data/y_train.npy', y_train)
    np.save('data/X_test.npy', X_test)
    np.save('data/y_test.npy', y_test)

    import json
    params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist()
    }
    with open('../models/scaler_params.json', 'w') as f:
        json.dump(params, f)
    print(f"Scaler saved. Training set: {X_train.shape}, Test set: {X_test.shape}")