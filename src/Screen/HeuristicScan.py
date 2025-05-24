import pefile,math,magic,re
from collections import Counter
suspicious_patterns = [re.compile(p) for p in [
    rb"eval\(", rb"exec\(", rb"base64\.b64decode", rb"os\.system\(",
    rb"subprocess\.Popen\(", rb"powershell", rb"cmd\.exe",
    rb"import socket", rb"import struct"
]]
mime_detector = magic.Magic(mime=True)
def calculate_entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    data_size = len(data)
    return -sum((count / data_size) * math.log2(count / data_size) for count in freq.values())
def analyze_pe_file(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read(4096)  
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        entropy = calculate_entropy(file_data)
        suspicious_sections = sum(1 for s in pe.sections if calculate_entropy(s.get_data()) > 7.0)
        score = (2 if entropy > 9 else 0)+(3 if suspicious_sections > 2 else 0) +(2 if pe.OPTIONAL_HEADER.AddressOfEntryPoint < 0x1000 else 0)
        return score >= 5
    except pefile.PEFormatError:
        return False
    except Exception:
        return False
def analyze_script_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read(5000)  
        return sum(bool(p.search(content)) for p in suspicious_patterns) >= 7
    except Exception:
        return False
def analyze_generic_file(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read(4096)
        return calculate_entropy(file_data) > 9
    except Exception:
        return False
def analyze_file(file_path):
    try:
        file_type = mime_detector.from_file(file_path)
        if "executable" in file_type:
            return analyze_pe_file(file_path)
        elif "script" in file_type or "text" in file_type:
            return analyze_script_file(file_path)
        else:
            return analyze_generic_file(file_path)
    except Exception:
        return False