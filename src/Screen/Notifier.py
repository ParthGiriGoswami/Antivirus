import os, sys, psutil, flet as ft, notifypy
from watchdog.events import FileSystemEventHandler
device_malware_files = set()
downloaded_malware_files = set()
malware_snackbar = None
device_scanned = False
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
def show_malware_overlay(page, malware_files, title_text):
    global malware_snackbar
    selected_files = set()
    checkboxes = []
    file_list_view = ft.ListView(expand=True, spacing=10)
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
        remove_button.disabled = True
        page.update()
    def on_checkbox_change(e, file_path):
        if e.control.value:
            selected_files.add(file_path)
        else:
            selected_files.discard(file_path)
        remove_button.disabled = len(selected_files) == 0
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
            ])
        ], spacing=10, tight=True),
    )
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
def notify_results(page, source):
    if source == "device":
        if not device_malware_files:
            send_notification("Information", "No malware files found on connected devices.")
            return
        send_notification("Information", f"{len(device_malware_files)} malware files found on devices.")
        show_malware_overlay(page, device_malware_files, "Device Malware List")
    elif source == "download":
        if not downloaded_malware_files:
            send_notification("Information", "No malware files detected in recent downloads.")
            return
        send_notification("Information", f"{len(downloaded_malware_files)} malware files detected in downloads.")
        show_malware_overlay(page, downloaded_malware_files, "Downloaded Malware List")
class DownloadHandler(FileSystemEventHandler):
    def __init__(self, page: ft.Page, compiled_rule):
        self.page = page
        self.rule = compiled_rule
    def on_created(self, event):
        if not event.is_directory:
            scan_directory(event.src_path, self.rule, "download")
            notify_results(self.page, "download")
def list_connected_devices(page, compiled_rule):
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
        notify_results(page, "device")
    elif not devices and device_scanned:
        device_scanned = False
        close_overlay(page)