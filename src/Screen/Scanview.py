from Screen.Helper import lock_folder,unlock_folder
import flet as ft,os
from Screen.scan import Scan
from Screen.Createbutton import button
from Screen.ScanDir import scan_directory
def on_folder_picked_for_quick_scan(e: ft.FilePickerResultEvent, page: ft.Page,rule,quickfiles,quickpath,exclusionfiles,VAULT_DIR):
    scanned=set()
    if e.path:
        try:
            unlock_folder()
            quick_file_path =f"{VAULT_DIR}/quickpath.txt"
            os.makedirs(os.path.dirname(quick_file_path), exist_ok=True)
            try:
                with open(quick_file_path, "a") as quick_file:
                    quick_file.write(f"{e.path}\n")
                    quickpath.add(e.path)
                    scanned.add(e.path)
                for file in scanned:
                    scan_directory(file,quickfiles)
            except:
                pass
        except:
            pass
        finally:
            lock_folder()
        if scanned:
            Scan(page,quickfiles,exclusionfiles,rule,False,VAULT_DIR)
def on_folder_picked_for_custom_scan(e: ft.FilePickerResultEvent, page: ft.Page,rule,exclusionfiles,VAULT_DIR):
    scanned=set()
    if e.path:
        try:
           scan_directory(e.path,scanned)
        except (PermissionError, FileNotFoundError):
            pass
        if scanned:
            Scan(page,scanned,exclusionfiles,rule,False,VAULT_DIR)
def ScanView(page: ft.Page,rule,quickfiles,quickpath,deepfiles,exclusionfiles,VAULT_DIR):
    file_picker_for_custom_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_custom_scan(e, page,rule,exclusionfiles,VAULT_DIR))
    page.overlay.append(file_picker_for_custom_scan)
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page,rule,quickfiles,quickpath,exclusionfiles,VAULT_DIR))
    page.overlay.append(file_picker_for_quick_scan)
    return ft.Container(
        expand=True,
        adaptive=True,
        margin=10,
        content=ft.Column(
            [
                ft.Text(value="Scans", size=20),
                button(page,"Quick Scan","Quickly scans high-risk areas for threats",icon=ft.Icons.SAVED_SEARCH,on_click=lambda _:file_picker_for_quick_scan.get_directory_path() if not quickfiles else Scan(page,quickfiles,exclusionfiles,rule,False,VAULT_DIR)),
                button(page,"Deep Scan","A full threat inspection for your entire device",icon=ft.Icons.SCREEN_SEARCH_DESKTOP_SHARP,on_click=lambda _:Scan(page,deepfiles,exclusionfiles,rule,True,VAULT_DIR)),
                button(page,"Custom Scan","Allows you to scan specific folders on your device",icon=ft.Icons.DASHBOARD_CUSTOMIZE_SHARP,on_click=lambda _: file_picker_for_custom_scan.get_directory_path()),
            ],
            spacing=21,
        ),
    )