import os
SAFE_PATHS = [os.path.abspath(p) for p in ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)"]]
def is_in_safe_path(file_path):
    file_path = os.path.abspath(file_path)
    return any(file_path.startswith(safe) for safe in SAFE_PATHS)
def scan_directory(directory, file_set):
    try:
        if "Screen" not in os.path.normpath(directory).split(os.sep) or not is_in_safe_path(directory):
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file():
                        file_set.add(entry.path)
                    elif  entry.is_dir(follow_symlinks=False):
                        scan_directory(entry.path, file_set)
    except (PermissionError, FileNotFoundError):
        pass
    return file_set