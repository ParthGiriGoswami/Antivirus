import flet as ft
from Screen.Createbutton import button
from Screen.ListFiles import listfiles
from Screen.Verify import verify_yourself
def options(page,quickpath,quickfile,exclusionfiles,pendrivefiles,VAULT_DIR):
    def close_bs(e):
        page.close(bs)
        page.update()
    bs = ft.AlertDialog(modal=True)
    cont = ft.Column([
        button(page,"Edit Quick files","Adds or remove files from quickscan list",icon=ft.Icons.ADD_BOX,on_click=lambda _:listfiles(page,idp="Quick List",path=quickpath,file=quickfile,VAULT_DIR=VAULT_DIR,back_cont=cont)),
        button(page,"Edit Exclusion files","Adds or remove files from exclusion list",icon=ft.Icons.ADD_BOX,on_click=lambda _:listfiles(page,idp="Exclusion List",path=exclusionfiles,VAULT_DIR=VAULT_DIR,back_cont=cont)),
        button(page,"Edit Pendrive files","Adds or remove files from pendrive lists",icon=ft.Icons.ADD_BOX,on_click=lambda _:listfiles(page,idp="Pendrive list",path=pendrivefiles,VAULT_DIR=VAULT_DIR,back_cont=cont)),
    ], spacing=21, expand=True)
    bs.title = ft.Row([
        ft.Text("Edit Files", size=20, weight=ft.FontWeight.BOLD),
        ft.Container(expand=True),
        ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs)
    ])
    bs.content = ft.Container(width=page.width, height=500, content=cont)
    bs.actions_alignment = ft.CrossAxisAlignment.END
    page.open(bs)
def SettingsView(page: ft.Page,quickpath,quickfile,exclusionfiles,pendrivefiles,VAULT_DIR, quarantinefiles):
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                ft.Text(value="Settings", size=20),
                button(page,"Edit Files","Edits files from quickscan, exclusion and pendrive",icon=ft.Icons.EDIT,on_click=lambda _: options(page,quickpath,quickfile,exclusionfiles,pendrivefiles,VAULT_DIR)),
                button(page,"File Decryption","Decrypt a file",icon=ft.Icons.LOCK_OPEN,on_click=lambda _:verify_yourself(page,"File Decryption",VAULT_DIR)), 
                button(page,"Unlock Folder","Unlocks any locked folder in the device",icon=ft.Icons.FOLDER,on_click=lambda _:verify_yourself(page,"Unlock Folder",VAULT_DIR)),
                button(page, "Quarantine Folder", "View quarantine folder", icon=ft.Icons.DATASET, on_click=lambda _: verify_yourself(page,"Quarantine Folder", VAULT_DIR, quarantinefiles))
            ],
            spacing=21,
        ),
    )