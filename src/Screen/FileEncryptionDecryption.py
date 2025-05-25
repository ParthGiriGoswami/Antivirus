from cryptography.fernet import Fernet
import os,flet as ft
def load_key(key_file):
    with open(key_file, "rb") as file:
        key=file.read()
    return key
def file_decryption(page:ft.Page,encrypted_file_path):
    def handle_close(e):
        page.close(dia)
    if not os.path.exists(encrypted_file_path):
        pass
    base_name=encrypted_file_path.replace(".encrypted","")
    key_file = f"{base_name}.key"
    key = load_key(key_file)
    fernet = Fernet(key)
    with open(encrypted_file_path, "rb") as file:
        encrypted_data = file.read()  
    decrypted_data = fernet.decrypt(encrypted_data)
    original_file = base_name
    with open(original_file, "wb") as file:
        file.write(decrypted_data)  
    dia = ft.AlertDialog(
        modal=True,
        title=ft.Text("Info"),
        content=ft.Text("File Decrypted"),
        actions=[
            ft.TextButton("Ok", on_click=handle_close),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        on_dismiss=lambda e: page.add(
            ft.Text("Modal dialog dismissed"),
        ),
    )
    page.open(dia)
    os.remove(encrypted_file_path)
    os.remove(key_file)
    return original_file
def generate_key(file_name):
    key_file = f"{file_name}.key"
    key = Fernet.generate_key()
    with open(key_file, "wb") as file:
        file.write(key)
    return key_file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()  
    encrypted_data = fernet.encrypt(file_data)  
    encrypted_file=file_path+".encrypted"
    with open(encrypted_file,"wb") as file:
        file.write(encrypted_data)
    os.remove(file_path)  
def file_encryption(page:ft.Page,file_path):
    def handle_close(e):
        page.close(dia)
    key_file = f"{file_path}.key"
    if file_path.endswith(".encrypted"):
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Info"),
            content=ft.Text("You have already encrypted the file"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(
                ft.Text("Modal dialog dismissed"),
            ),
        )
        page.open(dia)
        return
    if file_path.endswith(".key"):
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("Key files cannot be encrypted."),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
            on_dismiss=lambda e: page.add(
                ft.Text("Modal dialog dismissed"),
            ),
        )
        page.open(dia)
        return
    if not os.path.exists(key_file):
        generate_key(file_path)
    key = load_key(key_file)
    encrypt_file(file_path, key)
    dia = ft.AlertDialog(
        modal=True,
        title=ft.Text("Success"),
        content=ft.Text("File encrypted successfully"),
        actions=[
            ft.TextButton("Ok", on_click=handle_close),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        on_dismiss=lambda e: page.add(
            ft.Text("Modal dialog dismissed"),
        ),
    )
    page.open(dia)  