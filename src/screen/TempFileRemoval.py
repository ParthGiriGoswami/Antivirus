import flet as ft,os,tempfile
def temp_file_removal(page: ft.Page):
    def handle_close(e):
        page.close(dia)
    files=set()
    temp_dir = tempfile.gettempdir()
    for filename in os.listdir(temp_dir):
        file_path = os.path.join(temp_dir, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)  
                files.add(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
                files.add(file_path)
        except:
            pass
    if(len(files)==0):
        dia=ft.AlertDialog(
            modal=True,
            title=ft.Text("Info"),
            content=ft.Text("No temporary files"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(
                ft.Text("Modal dialog dismissed"),
            ),
        )
        page.open(dia)
    else:
        dia=ft.AlertDialog(
            modal=True,
            title=ft.Text("Info"),
            content=ft.Text(f"{len(files)} file(s) removed"),
            actions=[
                ft.TextButton("Ok", on_click=handle_close),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(
                ft.Text("Modal dialog dismissed"),
            ),
        )
        page.open(dia)