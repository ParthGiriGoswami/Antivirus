import flet as ft
from Screen.Createbutton import button
from Screen.TempFileRemoval import temp_file_removal
from Screen.Verify import verify_yourself
def ProtectionView(page: ft.Page,VAULT_DIR):
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                ft.Text(value="Protection", size=20),
                button(page,"File Encryption","Encrypts a file",icon=ft.Icons.LOCK,on_click=lambda _: verify_yourself(page,"File Encryption",VAULT_DIR)),
                button(page,"Temporary File Removal","Removes files that are stored in device",icon=ft.Icons.INSERT_DRIVE_FILE_SHARP,on_click=lambda _: temp_file_removal(page)),  
                button(page,"Password Manager","Manages passwords on this device",icon=ft.Icons.MANAGE_ACCOUNTS_ROUNDED,on_click=lambda _: verify_yourself(page,"Password Manager",VAULT_DIR)),
                button(page,"Lock Folder","Locks any folder in the device",icon=ft.Icons.FOLDER_OFF,on_click=lambda _:verify_yourself(page,"Lock Folder",VAULT_DIR)),    
            ],
            spacing=21,
        ),
    )