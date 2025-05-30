import os, platform, hashlib, flet as ft, ctypes
from cryptography.fernet import Fernet
from Screen.Helper import lock_folder, unlock_folder
IS_WINDOWS = platform.system() == "Windows"
FILE_ATTRIBUTE_READONLY = 0x01
FILE_ATTRIBUTE_NORMAL = 0x80
def key_filename(file_path, vault_dir):
    return os.path.join(vault_dir, f"{hashlib.sha256(file_path.encode()).hexdigest()}.bin")
def generate_key(file_path, vault_dir):
    key_path = key_filename(file_path, vault_dir)
    unlock_folder()
    with open(key_path, "wb") as f:
        f.write(Fernet.generate_key())
    if IS_WINDOWS:
        ctypes.windll.kernel32.SetFileAttributesW(key_path, FILE_ATTRIBUTE_READONLY)
    lock_folder()
    return key_path
def load_key(file_path, vault_dir):
    key_path = key_filename(file_path, vault_dir)
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found for {file_path}")
    with open(key_path, "rb") as f:
        return f.read()
def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        encrypted_data = Fernet(key).encrypt(f.read())
    with open(file_path + ".encrypted", "wb") as f:
        f.write(encrypted_data)
    os.remove(file_path)
def file_encryption(page: ft.Page, file_path, vault_dir):
    def show_dialog(title, message):
        dialog= ft.AlertDialog(
            modal=True,
            title=ft.Text(title),
            content=ft.Text(message),
            actions=[ft.TextButton("OK", on_click=lambda e: page.close(dialog))],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dialog)
    if file_path.endswith(".encrypted"):
        show_dialog("Error", "This file is already encrypted.")
    else:
        try:
            if not os.path.exists(key_filename(file_path, vault_dir)):
                generate_key(file_path, vault_dir)
            key = load_key(file_path, vault_dir)
            encrypt_file(file_path, key)
            show_dialog("Success", "File encrypted successfully.")
        except:
            pass
def file_decryption(page: ft.Page, encrypted_path, vault_dir):
    def show_dialog(title, message):
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(title),
            content=ft.Text(message),
            actions=[ft.TextButton("OK", on_click=lambda e: page.close(dialog))],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.open(dialog)
    if not os.path.exists(encrypted_path):
        show_dialog("Error", "Encrypted file not found.")
        return
    base_path = encrypted_path.replace(".encrypted", "")
    try:
        key = load_key(base_path, vault_dir)
        with open(encrypted_path, "rb") as f:
            decrypted_data = Fernet(key).decrypt(f.read())
        with open(base_path, "wb") as f:
            f.write(decrypted_data)
        os.remove(encrypted_path)
        key_path = key_filename(base_path, vault_dir)
        if os.path.exists(key_path):
            if IS_WINDOWS:
                ctypes.windll.kernel32.SetFileAttributesW(key_path, FILE_ATTRIBUTE_NORMAL)
            os.remove(key_path)
        show_dialog("Info", "File decrypted successfully.")
    except:
        pass