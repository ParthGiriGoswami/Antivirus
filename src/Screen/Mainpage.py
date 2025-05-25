import flet as ft, yara, psutil, threading, os, time, asyncio
from Screen.Protectionview import ProtectionView
from Screen.Settingsview import SettingsView
from Screen.Scanview import ScanView
from Screen.Homeview import HomeView
from Screen.Notifier import list_connected_devices, DownloadHandler
from Screen.ScanDir import scan_directory
from watchdog.observers import Observer
from Screen.Helper import lock_folder,unlock_folder
from concurrent.futures import ThreadPoolExecutor
file_lock = threading.Lock()
quickpath = set()
deepfiles = set()
quickfiles = set()
exclusionfiles=set()
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
    yara_rule = """
         rule MalwareDetection {
        strings:
            $ransomware = {50 53 51 52 56 57 55 41 54 41 55 41 56 41 57}
            $keylogger = {6A 00 68 00 30 00 00 64 FF 35 30 00 00 00}
            $shellcode = {31 C0 50 68 2E 65 78 65 68 63 61 6C 63 54 5F 50 57 56 50 FF D0}
            $cmd = "cmd.exe /c"
            $ps = "powershell.exe -nop -w hidden"
        condition:
            filesize < 2MB and (1 of ($ransomware, $keylogger, $shellcode) and 1 of ($cmd, $ps))
    }
    """
    compiled_rule = yara.compile(source=yara_rule)
    def get_download_dir():
        home = os.environ.get("USERPROFILE") or os.environ.get("HOME")
        return os.path.join(home, "Downloads")
    DOWNLOADS_DIR = get_download_dir()
    def download_monitor(page):
        handler = DownloadHandler(page, compiled_rule)
        observer = Observer()
        observer.schedule(handler, path=DOWNLOADS_DIR, recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    def device_monitor(page):
        while True:
            list_connected_devices(page, compiled_rule)
            time.sleep(1)
    def drive_monitor():
        global quickfiles
        while True:
            time.sleep(240)
            temp_files = set()
            get_drives(temp_files)
            with file_lock:
                if temp_files != quickfiles:
                    quickfiles.clear()
                    quickfiles.update(temp_files)
    threading.Thread(target=device_monitor, args=(page,), daemon=True).start()
    threading.Thread(target=download_monitor, args=(page,), daemon=True).start()
    image_width = 500
    animated_image = ft.AnimatedSwitcher(
        content=ft.Image(
            src="src/assets/icon.png",
            width=image_width,
            height=image_width,
            fit=ft.ImageFit.CONTAIN,
        ),
        transition=ft.AnimatedSwitcherTransition.SCALE,
        duration=500
    )
    animated_image_container = ft.Container(
        content=animated_image,
        height=image_width,
        alignment=ft.alignment.center
    )
    loading_indicator = ft.Container(
        content=ft.Column([animated_image_container,ft.Text("Scanning Files. Please wait......",size=20,weight=ft.FontWeight.BOLD)],
        alignment=ft.MainAxisAlignment.CENTER,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center,
        expand=True
    )
    animation_running=True
    async def animate_image():
        await asyncio.sleep(1)
        grow = True
        while animation_running:
            await asyncio.sleep(1.4)
            new_size = 0 if grow else 500
            grow = not grow
            animated_image.content = ft.Image(
                src="src/assets/icon.png",
                width=new_size,
                height=new_size,
                fit=ft.ImageFit.CONTAIN
            )
            animated_image.update() if animation_running==True else None
    content_container = ft.Container(content=loading_indicator, expand=True)
    navigation_rail = ft.NavigationRail(
        selected_index=0,
        bgcolor=ft.Colors.BLUE_GREY_900,
        destinations=[
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.HOME_OUTLINED, size=90),selected_icon=ft.Icon(ft.Icons.HOME, size=90),label_content=ft.Text("Home", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SEARCH, size=90),selected_icon=ft.Icon(ft.Icons.SEARCH, size=90),label_content=ft.Text("Scan", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SHIELD_OUTLINED, size=90),selected_icon=ft.Icon(ft.Icons.SHIELD, size=90),label_content=ft.Text("Protection", size=20)),
            ft.NavigationRailDestination(icon=ft.Icon(ft.Icons.SETTINGS_OUTLINED, size=90),selected_icon=ft.Icon(ft.Icons.SETTINGS, size=90),label_content=ft.Text("Settings", size=20)),
        ],
        expand=True,
        on_change=lambda e: change_page(e.control.selected_index),
        disabled=True
    )
    def change_page(index):
        if navigation_rail.disabled:
            return
        if index == 0:
            view = HomeView(page,compiled_rule,quickfiles,quickpath,exclusionfiles)
        elif index == 1:
            view = ScanView(page, compiled_rule, quickfiles, quickpath, deepfiles,exclusionfiles)
        elif index == 2:
            view = ProtectionView(page)
        else:
            view = SettingsView(page, quickpath, quickfiles,exclusionfiles)
        content_container.content = view
        page.update()
    def update_ui_after_scan():
        nonlocal animation_running
        navigation_rail.disabled = False
        content_container.content = HomeView(page,compiled_rule,quickfiles,quickpath,exclusionfiles)
        animation_running=False
        page.update()
    def init_scans():
        global quickfiles,exclusionfiles
        quickfiles.clear()
        get_drives(deepfiles)
        quick_scan_path = "files/quickpath.txt"
        unlock_folder()
        if os.path.exists(quick_scan_path):
            with open(quick_scan_path, 'r') as file:
                for line in file:
                    path = line.strip()
                    quickpath.add(path)
                    scan_directory(path, quickfiles)
        if os.path.exists("files/exclusion.txt"):
            with open("files/exclusion.txt", "r") as file:
                exclusionfiles=set(line.strip() for line in file)
        lock_folder()
        update_ui_after_scan()
    threading.Thread(target=init_scans, daemon=True).start()
    page.run_task(animate_image)
    return ft.View(
        route="/home",
        controls=[
            ft.Row([
                ft.Container(navigation_rail, expand=False, width=120),
                content_container
            ], expand=True)
        ],
        spacing=0,
        padding=0
    )