import flet as ft,os
from Screen.scan import Scan
from Screen.ScanDir import scan_directory
from Screen.Helper import lock_folder,unlock_folder
scanned=set()
def on_folder_picked_for_quick_scan(e: ft.FilePickerResultEvent, page: ft.Page,rule,quickfiles,quickpath,exclusionfiles):
    if e.path:
        try:
            quick_file_path = "files/quickpath.txt"
            os.makedirs(os.path.dirname(quick_file_path), exist_ok=True)
            try:
                unlock_folder()
                with open(quick_file_path, "a") as quick_file:
                    quick_file.write(f"{e.path}\n")
                    quickpath.add(e.path)
                    scanned.add(e.path)
                for file in scanned:
                    scan_directory(file,quickfiles)
            except:
                pass
            finally:
                lock_folder()
        except:
            pass
        if scanned:
            Scan(page,quickfiles,exclusionfiles,rule,False)
def HomeView(page: ft.Page,rule,quickfiles,quickpath,exclusionfiles):
    file_picker_for_quick_scan = ft.FilePicker(on_result=lambda e: on_folder_picked_for_quick_scan(e, page,rule,quickfiles,quickpath,exclusionfiles))
    page.overlay.append(file_picker_for_quick_scan)
    btn1 = ft.ElevatedButton(
        "Quick scan",
        on_click=lambda _:file_picker_for_quick_scan.get_directory_path() if not quickfiles else Scan(page,quickfiles,exclusionfiles,rule,False)
    )
    return ft.Container(
        expand=True,
        padding=10,
        content=ft.Column(
            [
                ft.Row([ft.Icon(name=ft.Icons.INFO_OUTLINED, size=200)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([ft.Text(value="Perform a scan", size=20)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([btn1], alignment=ft.MainAxisAlignment.CENTER)
            ],
            spacing=10,expand=True,alignment=ft.MainAxisAlignment.CENTER
        ),)