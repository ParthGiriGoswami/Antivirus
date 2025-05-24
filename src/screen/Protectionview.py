import flet as ft
from Screen.Createbutton import create_custom_button
from Screen.TempFileRemoval import temp_file_removal
from Screen.Verify import verify_yourself
def ProtectionView(page: ft.Page):
    return ft.Container(
        expand=True,
        padding=10,
        adaptive=True,
        content=ft.Column(
            [
                ft.Text(value="Protection", size=20),
                create_custom_button(page,"File Encryption","Encrypts a file",icon=ft.Icons.LOCK,on_click=lambda _: verify_yourself(page,"File Encryption")),
                create_custom_button(page,"Temporary File Removal","Removes files that are stored in device",icon=ft.Icons.INSERT_DRIVE_FILE_SHARP,on_click=lambda _: temp_file_removal(page)),  
                create_custom_button(page,"Password Manager","Manages passwords on this device",icon=ft.Icons.MANAGE_ACCOUNTS_ROUNDED,on_click=lambda _: verify_yourself(page,"Password Manager")),
                create_custom_button(page,"Lock Folder","Locks any folder in the device",icon=ft.Icons.FOLDER_OFF,on_click=lambda _:verify_yourself(page,"Lock Folder")),    
            ],
            spacing=21,
        ),
    )