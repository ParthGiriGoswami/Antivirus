import os, re, magic
from collections import Counter
suspicious_patterns = [
    (re.compile(rb"eval\("), 1),
    (re.compile(rb"exec\("), 1),
    (re.compile(rb"base64\.b64decode"), 1),
    (re.compile(rb"os\.system\("), 1),
    (re.compile(rb"subprocess\.Popen\("), 1),
    (re.compile(rb"powershell", re.IGNORECASE), 2),
    (re.compile(rb"cmd\.exe", re.IGNORECASE), 2),
    (re.compile(rb"import socket"), 1),
    (re.compile(rb"import struct"), 1),
    (re.compile(rb"powershell\s+-enc", re.IGNORECASE), 2),
    (re.compile(rb"certutil.*-decode", re.IGNORECASE), 2),
    (re.compile(rb"curl\s+http", re.IGNORECASE), 1),
    (re.compile(rb"wget\s+http", re.IGNORECASE), 1),
]
mime_detector = magic.Magic(mime=True)
def calculate_entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in freq.values())
def analyze_log_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read(10000)  
        score = 0
        for pattern, weight in suspicious_patterns:
            if pattern.search(content):
                score += weight
        return score >= 4 
    except Exception:
        return False
def analyze_file(file_path):
    try:
        if not file_path.lower().endswith(".log"):
            return False
        file_type = mime_detector.from_file(file_path).lower()
        if "text" in file_type or "log" in file_type:
            return analyze_log_file(file_path)
        return False
    except Exception:
        return False