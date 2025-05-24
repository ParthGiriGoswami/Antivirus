import flet as ft
from Screen.Createbutton import create_custom_button
from Screen.ListFiles import listfiles
from Screen.Verify import verify_yourself
def SettingsView(page: ft.Page,quickpath,quickfile,exclusionfiles):
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                ft.Text(value="Settings", size=20),
                create_custom_button(page,"Edit Quick files","Adds or remove files from quickscan list",icon=ft.Icons.ADD_BOX,on_click=lambda _: listfiles(page,idp="Quick List",path=quickpath,file=quickfile)),
                create_custom_button(page,"Edit Exclusion files","Adds or remove files from exclusion list",icon=ft.Icons.ADD_BOX,on_click=lambda _: listfiles(page,idp="Exclusion List",path=exclusionfiles)),
                create_custom_button(page,"File Decryption","Decrypt a file",icon=ft.Icons.LOCK_OPEN,on_click=lambda _:verify_yourself(page,"File Decryption")), 
                create_custom_button(page,"Unlock Folder","Unlocks any locked folder in the device",icon=ft.Icons.FOLDER,on_click=lambda _:verify_yourself(page,"Unlock Folder"))
            ],
            spacing=21,
        ),
    )