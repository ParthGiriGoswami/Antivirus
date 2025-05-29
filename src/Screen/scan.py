import flet as ft,threading,math
from Screen.Commonscan import scan_drives
malware_count = set()
def Scan(page: ft.Page, scanned,exclusionfiles,rule,flag,VAULT_DIR,quarantinefiles):
    count = len(scanned)
    malware_count.clear()
    txt = ft.Text(value="", width=600, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS, text_align=ft.TextAlign.CENTER)
    info = ft.Text(value="", text_align=ft.TextAlign.CENTER,style=ft.TextStyle(weight=ft.FontWeight.BOLD))
    progress = ft.ProgressBar(value=0.0, width=300, height=300, rotate=math.radians(-90),color=ft.Colors.BLUE_900)
    progress_ring = ft.Container(
        width=300,
        height=300,
        border_radius=150,
        alignment=ft.alignment.center,
        content=ft.Stack(
            controls=[
                ft.Container(content=progress,width=300,height=300,border_radius=150),
                ft.Container(content=info,alignment=ft.alignment.center),
            ]
        )
    )
    cont = ft.Container(
        padding=50,
        width=page.width,
        height=page.height,
        content=ft.Column(
            [progress_ring, txt],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        adaptive=True,
        alignment=ft.alignment.center,
    )
    bs = ft.AlertDialog(modal=True,title=ft.Text("Scanning",size=20, weight=ft.FontWeight.BOLD),content=cont,actions=None)
    page.open(bs)
    page.update()
    threading.Thread(target=scan_drives,args=(page,txt,info,count,scanned,progress,malware_count,rule,bs,flag,exclusionfiles,VAULT_DIR,quarantinefiles),daemon=True).start()