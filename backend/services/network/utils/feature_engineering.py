import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

CATEGORICAL_MAPPINGS = {
    'protocol_type': {'tcp': 0, 'udp': 1, 'icmp': 2},
    'service': {
        'http': 0, 'smtp': 1, 'ftp': 2, 'telnet': 3, 'ssh': 4,
        'pop_3': 5, 'imap': 6, 'finger': 7, 'auth': 8, 'domain': 9,
        'ftp_data': 10, 'other': 11
    },
    'flag': {
        'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3, 'SH': 4,
        'RSTOS0': 5, 'S1': 6, 'RSTR': 7, 'S2': 8, 'S3': 9,
        'OTH': 10
    }
}

def preprocess_flow(data):
    features = []
    
    for col in FEATURE_COLUMNS:
        if col in data:
            value = data[col]
            if col in CATEGORICAL_MAPPINGS:
                value = CATEGORICAL_MAPPINGS[col].get(value, 0)
            features.append(float(value))
        else:
            features.append(0.0)
    
    return features

def extract_flow_features(packet_data):
    features = {
        'duration': packet_data.get('duration', 0),
        'src_bytes': packet_data.get('src_bytes', 0),
        'dst_bytes': packet_data.get('dst_bytes', 0),
        'protocol_type': packet_data.get('protocol', 'tcp'),
        'service': packet_data.get('service', 'other'),
        'flag': packet_data.get('flag', 'SF'),
        'count': packet_data.get('count', 0),
        'srv_count': packet_data.get('srv_count', 0),
        'serror_rate': packet_data.get('serror_rate', 0),
        'srv_serror_rate': packet_data.get('srv_serror_rate', 0),
        'rerror_rate': packet_data.get('rerror_rate', 0),
        'srv_rerror_rate': packet_data.get('srv_rerror_rate', 0),
        'same_srv_rate': packet_data.get('same_srv_rate', 0),
        'diff_srv_rate': packet_data.get('diff_srv_rate', 0),
        'dst_host_count': packet_data.get('dst_host_count', 0),
        'dst_host_srv_count': packet_data.get('dst_host_srv_count', 0),
        'dst_host_same_srv_rate': packet_data.get('dst_host_same_srv_rate', 0),
        'dst_host_diff_srv_rate': packet_data.get('dst_host_diff_srv_rate', 0),
        'dst_host_serror_rate': packet_data.get('dst_host_serror_rate', 0),
        'dst_host_rerror_rate': packet_data.get('dst_host_rerror_rate', 0)
    }
    
    return features

def normalize_features(features):
    features_array = np.array(features)
    
    mean = np.mean(features_array)
    std = np.std(features_array)
    
    if std > 0:
        normalized = (features_array - mean) / std
    else:
        normalized = features_array - mean
    
    return normalized.tolist()
