import os, sys, psutil, flet as ft, notifypy,json
from watchdog.events import FileSystemEventHandler
from Screen.Helper import lock_folder,unlock_folder,get_vault_dir
VAULT_DIR=get_vault_dir().replace("\\","/")
device_malware_files = set()
downloaded_malware_files = set()
malware_snackbar = None
device_scanned = False
device_exclusions = set()  
download_exclusions = set()
def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)
def get_icon_path():
    path = "src/assets/icon.ico" if os.name == "nt" else "src/assets/icon.png"
    full_path = resource_path(path)
    return full_path if os.path.exists(full_path) else None
def send_notification(title, message):
    notification = notifypy.Notify()
    notification.application_name = "Kepler Antivirus"
    notification.title = title
    notification.message = message
    notification.urgency = "critical"
    notification.icon = get_icon_path()
    notification.send(block=False)
def scan_directory(path, compiled_rule, source_type):
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.is_file():
                    if compiled_rule.match(entry.path):
                        if source_type == "device":
                            device_malware_files.add(entry.path)
                        else:
                            downloaded_malware_files.add(entry.path)
                elif entry.is_dir(follow_symlinks=False):
                    scan_directory(entry.path, compiled_rule, source_type)
    except:
        pass
def show_malware_overlay(page, malware_files, title_text,exclusionfiles):
    global malware_snackbar
    selected_files = set()
    checkboxes = []
    file_list_view = ft.ListView(expand=True, spacing=10)
    def get_device_identifier(file_path):
        for partition in psutil.disk_partitions():
            if file_path.startswith(partition.mountpoint):
                return partition.device
        return "unknown"
    def load_exclusions():
        global device_exclusions, download_exclusions
        unlock_folder()
        if os.path.exists(f"{VAULT_DIR}/exclusion.json"):
            with open(f"{VAULT_DIR}/exclusion.json", "r") as f:
                device_exclusions = set(tuple(x) for x in json.load(f))
        if os.path.exists(f"{VAULT_DIR}/exclusion.txt"):
            with open(f"{VAULT_DIR}/exclusion.txt", "r") as f:
                download_exclusions = set(line.strip() for line in f)
        lock_folder()
    def save_device_exclusions():
        unlock_folder()
        with open(f"{VAULT_DIR}/exclusion.json", "w") as f:
            json.dump(list(device_exclusions), f)
        lock_folder()
    def save_download_exclusions():
        unlock_folder()
        with open(f"{VAULT_DIR}/exclusion.txt", "w") as f:
            f.write("\n".join(sorted(download_exclusions)))
        lock_folder()
    def add_to_exclusion_list(e):
        if title_text == "Device Malware List":
            for path in selected_files:
                device_id = get_device_identifier(path)
                file_key = (device_id, os.path.basename(path))
                device_exclusions.add(file_key)
                device_malware_files.discard(path)
            save_device_exclusions()
        else:
            for path in selected_files:
                download_exclusions.add(path)
                downloaded_malware_files.discard(path)
            save_download_exclusions()
        for cb in list(checkboxes):
            if cb.label in selected_files:
                file_list_view.controls.remove(cb)
                checkboxes.remove(cb)
        selected_files.clear()
        remove_button.disabled = add_button.disabled = True
        page.update()
    def remove_selected_files(e):
        removed = []
        for cb in checkboxes:
            if cb.label in selected_files:
                try:
                    os.remove(cb.label)
                    malware_files.discard(cb.label)
                    removed.append(cb)
                except:
                    pass
        for cb in removed:
            file_list_view.controls.remove(cb)
            checkboxes.remove(cb)
        selected_files.clear()
        remove_button.disabled=True
        add_button.disabled=True
        page.update()
    def on_checkbox_change(e, file_path):
        if e.control.value:
            selected_files.add(file_path)
        else:
            selected_files.discard(file_path)
        remove_button.disabled = len(selected_files) == 0
        add_button.disabled = len(selected_files) == 0
        page.update()       
    for file_path in sorted(malware_files):
        cb = ft.Checkbox(label=file_path, on_change=lambda e, fp=file_path: on_checkbox_change(e, fp))
        checkboxes.append(cb)
        file_list_view.controls.append(cb)
    dialog_card = ft.Container(
        width=1190,
        height=640,
        bgcolor="#272A2F",
        border_radius=24,
        padding=20,
        content=ft.Column([
            ft.Row([
                ft.Text(title_text, size=18, weight=ft.FontWeight.BOLD),
                ft.Container(expand=True),
                ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=lambda e: close_overlay(page))
            ]),
            ft.Container(content=file_list_view, expand=True, padding=10),
            ft.Row([
                ft.TextButton("Remove Selected", disabled=True, on_click=remove_selected_files),
                ft.TextButton("Add to exclusion list",disabled=True,on_click=add_to_exclusion_list)
            ])
        ], spacing=10, tight=True),
    )
    add_button=dialog_card.content.controls[2].controls[1]
    remove_button = dialog_card.content.controls[2].controls[0]
    malware_snackbar = ft.Stack(
        controls=[
            ft.Container(bgcolor=ft.Colors.BLACK54,expand=True,on_click=lambda e: None),
            ft.Container(content=dialog_card,alignment=ft.alignment.center)
        ]
    )
    page.overlay.append(malware_snackbar)
    page.update()
def close_overlay(page):
    global malware_snackbar
    if malware_snackbar and malware_snackbar in page.overlay:
        page.overlay.remove(malware_snackbar)
        malware_snackbar = None
        page.update()
def notify_results(page, source,exclusionfiles):
    if source == "device":
        if not device_malware_files:
            send_notification("Information", "No malware files found on connected devices.")
            return
        send_notification("Information", f"{len(device_malware_files)} malware files found on devices.")
        show_malware_overlay(page, device_malware_files, "Device Malware List",exclusionfiles)
    elif source == "download":
        if not downloaded_malware_files:
            send_notification("Information", "No malware files detected in recent downloads.")
            return
        send_notification("Information", f"{len(downloaded_malware_files)} malware files detected in downloads.")
        show_malware_overlay(page, downloaded_malware_files, "Downloaded Malware List",exclusionfiles)
class DownloadHandler(FileSystemEventHandler):
    def __init__(self, page: ft.Page, compiled_rule,exclusionfiles):
        self.page = page
        self.rule = compiled_rule
        self.exclusion=exclusionfiles
    def on_created(self, event):
        if not event.is_directory:
            scan_directory(event.src_path, self.rule, "download")
            notify_results(self.page, "download",self.exclusionfiles)
def list_connected_devices(page, compiled_rule,pendrivefiles):
    global device_scanned
    partitions = psutil.disk_partitions()
    devices = [
        partition.device
        for partition in partitions
        if 'removable' in partition.opts or partition.fstype in ['vfat', 'exfat', 'ntfs']
    ]
    if devices and not device_scanned:
        device_scanned = True
        for device in devices:
            scan_directory(device, compiled_rule, "device")
        notify_results(page, "device",pendrivefiles)
    elif not devices and device_scanned:
        device_scanned = False
        close_overlay(page)