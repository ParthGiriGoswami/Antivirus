import os,flet as ft,subprocess,platform,stat
os.environ["FLET_LOG_LEVEL"] = "none"
def toggle_folder_permission(e: ft.FilePickerResultEvent, page: ft.Page, lock: bool):
    if not e.path:
        return
    def handle_close(_):
        page.close(dialog)
    system = platform.system()
    folder_path = e.path
    try:
        if system == "Windows":
            command = f'icacls "{folder_path}" /{"deny everyone:F" if lock else "remove:d everyone"}'
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system in ("Linux", "Darwin"):
            permission = stat.S_IRWXU if lock else (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            os.chmod(folder_path, permission)
        message = f"{folder_path} {'locked' if lock else 'unlocked'} successfully"
    except Exception as ex:
        message = f"Failed to {'lock' if lock else 'unlock'}: {ex}"
    dialog = ft.AlertDialog(
        title=ft.Text("Info"),
        content=ft.Text(message),
        modal=True,
        actions=[ft.TextButton("OK", on_click=handle_close)],
        actions_alignment=ft.MainAxisAlignment.END,
        on_dismiss=lambda _: None
    )
    page.open(dialog)
def folder_locker(e, page): 
    toggle_folder_permission(e, page, lock=True)
def folder_unlocker(e, page):   
    toggle_folder_permission(e, page, lock=False)