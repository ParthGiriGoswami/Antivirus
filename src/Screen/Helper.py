import os,subprocess,platform,stat
path ="files"
def lock_folder():
    system = platform.system()
    if system == "Windows":
        try:
            subprocess.run(f'icacls "{path}" /reset', shell=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(f'icacls "{path}" /deny everyone:F', shell=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    elif system in ("Linux", "Darwin"):
        try:
            os.chmod(path, stat.S_IRWXU)  
        except:
            pass
def unlock_folder():
    system = platform.system()
    if system == "Windows":
        try:
            subprocess.run(f'icacls "{path}" /remove:d everyone', shell=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    elif system in ("Linux", "Darwin"):
        try:
            os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                     stat.S_IROTH | stat.S_IXOTH)
        except:
            pass