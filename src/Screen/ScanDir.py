import os
def scan_directory(directory, file_set):
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_file():
                    file_set.add(entry.path)
                elif  entry.is_dir(follow_symlinks=False):
                    scan_directory(entry.path, file_set)
    except (PermissionError, FileNotFoundError):
        pass
    return file_set