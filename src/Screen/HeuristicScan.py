import pefile,math,magic,re
from collections import Counter
suspicious_patterns = [
    (re.compile(rb"eval\("),1),(re.compile(rb"exec\("),1),(re.compile(rb"base64\.b64decode"),1),
    (re.compile(rb"os\.system\("),1),(re.compile(rb"subprocess\.Popen\("),1),(re.compile(rb"powershell"),2),
    (re.compile(rb"cmd\.exe"),2),(re.compile(rb"import socket"),1),(re.compile(rb"import struct"),1)
]
mime_detector = magic.Magic(mime=True)
def calculate_entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    size = len(data)
    return -sum((count/size) * math.log2(count/size) for count in freq.values())
def analyze_pe_file(file_path):
    try:
        with open(file_path,"rb") as f:
            header_data=f.read(4096)
        entropy=calculate_entropy(header_data)
        pe=pefile.PE(file_path)
        pe.parse_data_directories()
        suspicious_sections=sum(1 for s in pe.sections if calculate_entropy(s.get_data())>7.0)
        score=0
        if entropy>9:score+=2
        if suspicious_sections>2:score+=3
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint<0x1000:score+=2
        return score>=5
    except pefile.PEFormatError:
        return False
    except Exception:
        return False
def analyze_script_file(file_path):
    try:
        with open(file_path,"rb") as f:
            content=f.read(10000)
        score = 0
        for pattern,weight in suspicious_patterns:
            if pattern.search(content):
                score+=weight
        return score>=4
    except Exception:
        return False
def analyze_generic_file(file_path):
    try:
        with open(file_path,"rb") as f:
            data=f.read(4096)
        return len(data)>1000 and calculate_entropy(data)>9
    except Exception:
        return False
def analyze_file(file_path):
    try:
        file_type = mime_detector.from_file(file_path).lower()
        if "x-dosexec" in file_type or "x-executable" in file_type:
            return analyze_pe_file(file_path)
        elif "script" in file_type or "text" in file_type:
            return analyze_script_file(file_path)
        else:
            return analyze_generic_file(file_path)
    except Exception:
        return False