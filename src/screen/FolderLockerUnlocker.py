import os,flet as ft,subprocess,platform,stat
os.environ["FLET_LOG_LEVEL"] = "none"
def folder_unlocker(e: ft.FilePickerResultEvent, page: ft.Page):
    def handle_close(e):
        page.close(dia)
    if e.path:
        system = platform.system()
        if system == "Windows":
            command = f'icacls "{e.path}" /remove:d everyone'
            try:
                subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                cont = ft.Text(f"{e.path} unlocked successfully")
            except Exception as ex:
                cont = ft.Text(f"Failed to unlock: {ex}")
        elif system in ("Linux", "Darwin"):
            try:
                os.chmod(e.path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                cont = ft.Text(f"{e.path} unlocked successfully")
            except Exception as ex:
                cont = ft.Text(f"Failed to unlock: {ex}")
        else:
            cont = ft.Text("Can't unlock the folder")
        dia = ft.AlertDialog(
            content=cont,
            modal=True,
            title=ft.Text("Info"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(ft.Text("Modal dialog dismissed")),
        )
        page.open(dia)
def folder_locker(e: ft.FilePickerResultEvent, page: ft.Page):
    def handle_close(e):
        page.close(dia)
    if e.path:
        system = platform.system()
        if system == "Windows":
            command = f'icacls "{e.path}" /deny everyone:F'
            try:
                subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                cont = ft.Text(f"{e.path} locked successfully")
            except Exception as ex:
                cont = ft.Text(f"Failed to lock: {ex}")
        elif system in ("Linux", "Darwin"):
            try:
                os.chmod(e.path, stat.S_IRWXU)
                cont = ft.Text(f"{e.path} locked successfully")
            except Exception as ex:
                cont = ft.Text(f"Failed to lock: {ex}")
        else:
            cont = ft.Text("Can't lock the folder")
        dia = ft.AlertDialog(
            content=cont,
            modal=True,
            title=ft.Text("Info"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(ft.Text("Modal dialog dismissed")),
        )
        page.open(dia)