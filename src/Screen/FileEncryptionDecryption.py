import os
import platform
import hashlib
from Screen.Helper import lock_folder, unlock_folder
from cryptography.fernet import Fernet
import flet as ft
def key_filename(file_path,VAULT_DIR):
    hashed = hashlib.sha256(file_path.encode('utf-8')).hexdigest()
    return os.path.join(VAULT_DIR, f"{hashed}.bin")
def generate_key(file_path,VAULT_DIR):
    key_path = key_filename(file_path,VAULT_DIR)
    key = Fernet.generate_key()
    unlock_folder()
    with open(key_path, "wb") as f:
        f.write(key)
    if platform.system() == "Windows":
        import ctypes
        FILE_ATTRIBUTE_READONLY = 0x01
        ctypes.windll.kernel32.SetFileAttributesW(key_path, FILE_ATTRIBUTE_READONLY)
    lock_folder()
    return key_path
def load_key(file_path,VAULT_DIR):
    key_path = key_filename(file_path,VAULT_DIR)
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found for {file_path}")
    with open(key_path, "rb") as f:
        return f.read()
def encrypt_file(file_path,key):
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = fernet.encrypt(file_data)
    encrypted_file = file_path + ".encrypted"
    with open(encrypted_file, "wb") as f:
        f.write(encrypted_data)
    os.remove(file_path)
def file_encryption(page:ft.Page,file_path,VAULT_DIR):
    def handle_close(e):
        page.close(dia)
    if not os.path.exists(key_filename(file_path,VAULT_DIR)):
        generate_key(file_path,VAULT_DIR)
    try:
        key = load_key(file_path,VAULT_DIR)
    except Exception as e:
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text(f"Failed to load key: {e}"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dia)
        return
    encrypt_file(file_path, key)
    dia = ft.AlertDialog(
        modal=True,
        title=ft.Text("Success"),
        content=ft.Text("File encrypted successfully."),
        actions=[ft.TextButton("Ok", on_click=handle_close)],
        actions_alignment=ft.MainAxisAlignment.END,
    )
    page.open(dia)
def file_decryption(page: ft.Page, encrypted_file_path,VAULT_DIR):
    def handle_close(e):
        page.close(dia)
    if not os.path.exists(encrypted_file_path):
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text("Encrypted file not found."),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dia)
        return
    base_name = encrypted_file_path.replace(".encrypted", "")
    try:
        key = load_key(base_name,VAULT_DIR)
    except Exception as e:
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text(f"Key file missing or invalid: {e}"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dia)
        return
    fernet = Fernet(key)
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        dia = ft.AlertDialog(
            modal=True,
            title=ft.Text("Error"),
            content=ft.Text(f"Decryption failed: {e}"),
            actions=[ft.TextButton("Ok", on_click=handle_close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dia)
        return
    with open(base_name, "wb") as f:
        f.write(decrypted_data)
    dia = ft.AlertDialog(
        modal=True,
        title=ft.Text("Info"),
        content=ft.Text("File decrypted successfully."),
        actions=[ft.TextButton("Ok", on_click=handle_close)],
        actions_alignment=ft.MainAxisAlignment.END,
    )
    page.open(dia)
    os.remove(encrypted_file_path)
    try:
        key_path = key_filename(base_name,VAULT_DIR)
        if os.path.exists(key_path):
            if platform.system()=="Windows":
                import ctypes
                FILE_ATTRIBUTE_NORMAL = 0x80
                ctypes.windll.kernel32.SetFileAttributesW(key_path, FILE_ATTRIBUTE_NORMAL)
            os.remove(key_path)
    except:
        pass
