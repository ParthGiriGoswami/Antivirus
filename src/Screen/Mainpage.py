import flet as ft, yara, psutil, threading, os, time, asyncio,json,sqlite3
from datetime import datetime, timedelta
from Screen.Protectionview import ProtectionView
from Screen.Settingsview import SettingsView
from Screen.Scanview import ScanView
from Screen.Homeview import HomeView
from Screen.Notifier import list_connected_devices, DownloadHandler
from Screen.ScanDir import scan_directory
from watchdog.observers import Observer
from Screen.Helper import lock_folder,unlock_folder,get_vault_dir
from concurrent.futures import ThreadPoolExecutor
file_lock = threading.Lock()
quickpath = set()
deepfiles = set()
quickfiles = set()
exclusionfiles=set()
pendrivefiles=set()
quarantinefiles= set()
def init_quarantine_db(VAULT_DIR):
    db_path = os.path.join(VAULT_DIR, "quarantine.db")
    os.makedirs(VAULT_DIR, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, original_path TEXT NOT NULL,quarantine_path TEXT NOT NULL,timestamp TEXT NOT NULL)""")
def cleanup_quarantine(VAULT_DIR):
    try:
        unlock_folder()
        db_path = os.path.join(VAULT_DIR, "quarantine.db")
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cutoff_date = datetime.now() - timedelta(days=1)
            cursor.execute("SELECT id, quarantine_path, timestamp FROM quarantine")
            entries = cursor.fetchall()
            for entry_id, path, ts in entries:
                try:
                    file_time = datetime.fromisoformat(ts)
                    if file_time < cutoff_date:
                        if os.path.exists(path):
                            os.remove(path)
                        cursor.execute("DELETE FROM quarantine WHERE id = ?", (entry_id,))
                except:
                    pass
            conn.commit()
        lock_folder()
    except:
        pass
def fetch_quarantine_records(vault_dir):
    db_path = os.path.join(vault_dir, "quarantine.db")
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT filename, original_path, quarantine_path, timestamp FROM quarantine")
            for row in cursor.fetchall():
                quarantinefiles.add(tuple(row))  
    except:
        pass
def get_drives(file):
    partitions = psutil.disk_partitions()
    drive_letters = [p.device for p in partitions if p.fstype]
    def scan_drive(drive):
        local_files = scan_directory(drive,set())
        with file_lock:
            file.update(local_files)
        return len(local_files)
    max_workers = min(len(drive_letters), os.cpu_count())
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(scan_drive, drive_letters))
def MainPage(page: ft.Page):
    global quickfiles
    yara_rule = r"""
        rule MalwareDetection {
            strings:
                $ransomware = {50 53 51 52 56 57 55 41 54 41 55 41 56 41 57}
                $keylogger = {6A 00 68 00 30 00 00 64 FF 35 30 00 00 00}
                $shellcode = {31 C0 50 68 2E 65 78 65 68 63 61 6C 63 54 5F 50 57 56 50 FF D0}
                $cmd = "cmd.exe /c"
                $ps = "powershell.exe -nop -w hidden"
                $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            condition:
                filesize < 2MB and (
                    1 of ($ransomware, $keylogger, $shellcode) and 1 of ($cmd, $ps)
                    or $eicar
                )
        }
    """
    compiled_rule = yara.compile(source=yara_rule)
    VAULT_DIR = get_vault_dir().replace("\\", "/")
    DOWNLOADS_DIR = os.path.join(os.environ.get("USERPROFILE") or os.environ.get("HOME"), "Downloads")
    image_width = 500
    animated_image = ft.AnimatedSwitcher(
        content=ft.Image(src="src/assets/icon.png", width=image_width, height=image_width, fit=ft.ImageFit.CONTAIN),
        transition=ft.AnimatedSwitcherTransition.SCALE, duration=500
    )
    loading_indicator = ft.Container(
        content=ft.Column([
            ft.Container(content=animated_image, height=image_width, alignment=ft.alignment.center),
            ft.Text("Scanning Files. Please wait......", size=20, weight=ft.FontWeight.BOLD)
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center, expand=True
    )
    content_container = ft.Container(content=loading_indicator, expand=True)
    navigation_rail = ft.NavigationRail(
        selected_index=0,
        bgcolor=ft.Colors.BLUE_GREY_900,
        destinations=[
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.HOME_OUTLINED, size=90), selected_icon=ft.Icon(ft.Icons.HOME, size=90), label_content=ft.Text("Home", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SEARCH, size=90), selected_icon=ft.Icon(ft.Icons.SEARCH, size=90), label_content=ft.Text("Scan", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SHIELD_OUTLINED, size=90), selected_icon=ft.Icon(ft.Icons.SHIELD, size=90), label_content=ft.Text("Protection", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SETTINGS_OUTLINED, size=90), selected_icon=ft.Icon(ft.Icons.SETTINGS, size=90), label_content=ft.Text("Settings", size=20)),
        ],
        expand=True,
        on_change=lambda e: change_page(e.control.selected_index),disabled=True)
    animation_running = True
    async def animate_image():
        await asyncio.sleep(1)
        grow = True
        while animation_running:
            await asyncio.sleep(1.4)
            new_size = 0 if grow else image_width
            grow = not grow
            animated_image.content = ft.Image(src="src/assets/icon.png", width=new_size, height=new_size, fit=ft.ImageFit.CONTAIN)
            page.update()
    def change_page(index):
        if navigation_rail.disabled:
            return
        views = [HomeView, ScanView, ProtectionView, SettingsView]
        view_args = [
            (page, compiled_rule, quickfiles, quickpath, exclusionfiles, VAULT_DIR, quarantinefiles),
            (page, compiled_rule, quickfiles, quickpath, deepfiles, exclusionfiles, VAULT_DIR, quarantinefiles),
            (page, VAULT_DIR),
            (page, quickpath, quickfiles, exclusionfiles, pendrivefiles, VAULT_DIR, quarantinefiles)
        ]
        content_container.content = views[index](*view_args[index])
        page.update()
    def update_ui_after_scan():
        nonlocal animation_running
        navigation_rail.disabled = False
        content_container.content = HomeView(page, compiled_rule, quickfiles, quickpath, exclusionfiles, VAULT_DIR, quarantinefiles)
        animation_running = False
        page.update()
    def device_monitor():
        while True:
            list_connected_devices(page, compiled_rule, pendrivefiles)
            time.sleep(1)
    def download_monitor():
        handler = DownloadHandler(page, compiled_rule, exclusionfiles)
        observer = Observer()
        observer.schedule(handler, path=DOWNLOADS_DIR, recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()
    def drive_monitor():
        global deepfiles
        time.sleep(300)
        previous_drive_state = set(p.device for p in psutil.disk_partitions() if p.fstype)
        while True:
            current_drive_state = set(p.device for p in psutil.disk_partitions() if p.fstype)
            if current_drive_state != previous_drive_state:
                temp_files = set()
                get_drives(temp_files)
                with file_lock:
                    deepfiles.clear()
                    deepfiles.update(temp_files)
                previous_drive_state = current_drive_state
            time.sleep(1)  
    def init_scans():
        global quickfiles, exclusionfiles, pendrivefiles
        quickfiles.clear()
        unlock_folder()
        quick_scan_path = os.path.join(VAULT_DIR, "quickpath.txt")
        if os.path.exists(quick_scan_path):
            with open(quick_scan_path, 'r') as f:
                for line in f:
                    path = line.strip()
                    quickpath.add(path)
                    scan_directory(path, quickfiles)
        exclusion_path = os.path.join(VAULT_DIR, "exclusion.txt")
        if os.path.exists(exclusion_path):
            with open(exclusion_path, 'r') as f:
                exclusionfiles = set(line.strip() for line in f)

        exclusion_json_path = os.path.join(VAULT_DIR, "exclusion.json")
        if os.path.exists(exclusion_json_path):
            try:
                with open(exclusion_json_path, 'r') as f:
                    data = json.load(f)
                    pendrivefiles = set(tuple(entry) for group in data for entry in group)
            except Exception:
                pendrivefiles = set()
        init_quarantine_db(VAULT_DIR)
        cleanup_quarantine(VAULT_DIR)
        fetch_quarantine_records(VAULT_DIR)
        lock_folder()
        threading.Thread(target=device_monitor, daemon=True).start()
        threading.Thread(target=download_monitor, daemon=True).start()
        threading.Thread(target=cleanup_quarantine, args=(VAULT_DIR,), daemon=True).start()
        threading.Thread(target=drive_monitor, daemon=True).start()
        get_drives(deepfiles)
        update_ui_after_scan()
    threading.Thread(target=init_scans, daemon=True).start()
    page.run_task(animate_image)
    return ft.View(
        route="/home",
        controls=[ft.Row([ft.Container(navigation_rail, expand=False, width=120), content_container], expand=True)],
        spacing=0,
        padding=0
    )