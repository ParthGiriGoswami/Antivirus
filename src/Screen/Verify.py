import sqlite3,flet as ft,os,hashlib,hmac
from Screen.Helper import lock_folder,unlock_folder
def hash_value(value: str, salt: bytes):
    return hashlib.pbkdf2_hmac('sha256', value.encode(), salt, 100000)
def file_decryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    if e.files and len(e.files) > 0:
        file = e.files[0].path
        if file.endswith(".encrypted"):
            from Screen.FileEncryptionDecryption import file_decryption
            file_decryption(page, file)
        else:
            bs = ft.AlertDialog(
                modal=True,
                title=ft.Text("Info"),
                content=ft.Text("First encrypt the file"),
                actions=[ft.TextButton("Ok", on_click=lambda e: page.dialog.open(False))],
                actions_alignment=ft.MainAxisAlignment.END
            )
            page.open(bs)
            page.update()
def file_encryptor(e: ft.FilePickerResultEvent, page: ft.Page):
    if e.files and len(e.files) > 0:
        from Screen.FileEncryptionDecryption import file_encryption
        file_encryption(page, e.files[0].path)
def verify_yourself(page: ft.Page, idx: str):
    from Screen.PasswordManager import passwordmanager
    from Screen.FolderLockerUnlocker import folder_locker, folder_unlocker
    lock = ft.FilePicker(on_result=lambda e: folder_locker(e, page))
    unlock = ft.FilePicker(on_result=lambda e: folder_unlocker(e, page))
    file_encrypt = ft.FilePicker(on_result=lambda e: file_encryptor(e, page))
    file_decrypt = ft.FilePicker(on_result=lambda e: file_decryptor(e, page))
    page.overlay.extend([lock, unlock, file_encrypt, file_decrypt])
    def navigator():
        match idx:
            case "Password Manager": passwordmanager(page)
            case "Lock Folder": lock.get_directory_path()
            case "Unlock Folder": unlock.get_directory_path()
            case "File Encryption": file_encrypt.pick_files(allow_multiple=False)
            case "File Decryption": file_decrypt.pick_files(allow_multiple=False, allowed_extensions=["encrypted"])
    bs = ft.AlertDialog(modal=True,actions_alignment=ft.MainAxisAlignment.END)
    def fetch_config():
        with sqlite3.connect("files/config.enc") as conn:
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS passwords (salt BLOB NOT NULL,password BLOB NOT NULL,question TEXT,answer BLOB)')
            cursor.execute('SELECT salt, password, question, answer FROM passwords LIMIT 1')
            return cursor.fetchone()
    unlock_folder()
    stored = fetch_config()
    lock_folder()
    def close_dialog():
        page.close(bs)
        page.update()
    def show_question_dialog():
        salt, _, question_text, answer_hash = stored
        answer_field = ft.TextField(label="Answer", password=True, can_reveal_password=True)
        def verify_answer(e):
            answer = answer_field.value.strip()
            if answer and hmac.compare_digest(hash_value(answer.lower(), salt), answer_hash):
                close_dialog()
                show_reset_pin_dialog(salt)
            else:
                answer_field.error_text="Incorrect answer"
                page.update()
        bs.title=ft.Text("Answer Security Question")
        bs.content=ft.Column([
                ft.Text(f"Security Question:{question_text}"),
                answer_field
            ], height=70)
        bs.actions=[
                ft.TextButton("Submit",on_click=verify_answer),
                ft.TextButton("Cancel", on_click=lambda e: close_dialog())
            ]
        page.open(bs)
        page.update()
    def show_reset_pin_dialog(salt):
        new_pin = ft.TextField(label="New 4-digit PIN", password=True, can_reveal_password=True,
                               max_length=4, keyboard_type=ft.KeyboardType.NUMBER,
                               input_filter=ft.InputFilter(allow=True, regex_string=r"^\d*$"))
        confirm_pin = ft.TextField(label="Confirm PIN", password=True, can_reveal_password=True,
                                   max_length=4, keyboard_type=ft.KeyboardType.NUMBER,
                                   input_filter=ft.InputFilter(allow=True, regex_string=r"^\d*$"))
        def reset_pin(e):
            npin, cpin = new_pin.value.strip(), confirm_pin.value.strip()
            valid = True
            if len(npin) != 4 or not npin.isdigit():
                new_pin.error_text="PIN must be 4 digits"
                valid = False
            else:
                new_pin.error_text=None
            if npin!=cpin:
                confirm_pin.error_text="PINs do not match"
                valid = False
            else:
                confirm_pin.error_text=None

            if not valid:
                page.update()
                return
            unlock_folder()
            with sqlite3.connect("files/config.enc") as conn:
                conn.execute("UPDATE passwords SET password = ?", (hash_value(npin, salt),))
                conn.commit()
            lock_folder()
            close_dialog()
            navigator()
        bs.title=ft.Text("Reset PIN")
        bs.content=ft.Column([new_pin, confirm_pin], tight=True)
        bs.actions=[ft.TextButton("Submit", on_click=reset_pin),ft.TextButton("Cancel", on_click=lambda e: close_dialog())]
        page.open(bs)
        page.update()
    def show_initial_setup_dialog():
        pin_field = ft.TextField(label="Set 4-digit PIN", password=True, can_reveal_password=True,
                                 max_length=4, keyboard_type=ft.KeyboardType.NUMBER,
                                 input_filter=ft.InputFilter(allow=True, regex_string=r"^\d*$"))
        question_field = ft.TextField(label="Security Question")
        answer_field = ft.TextField(label="Answer", password=True, can_reveal_password=True)
        def set_initial_password(e):
            pin, question, answer = pin_field.value.strip(), question_field.value.strip(), answer_field.value.strip()
            valid = True
            if len(pin) != 4 or not pin.isdigit():
                pin_field.error_text = "PIN must be 4 digits"
                valid = False
            if not question:
                question_field.error_text = "Required"
                valid = False
            if not answer:
                answer_field.error_text = "Required"
                valid = False
            if not valid:
                page.update()
                return
            salt = os.urandom(16)
            pin_hash = hash_value(pin, salt)
            answer_hash = hash_value(answer.lower(), salt)
            unlock_folder()
            with sqlite3.connect("files/config.enc") as conn:
                conn.execute(
                    "INSERT INTO passwords (salt, password, question, answer) VALUES (?, ?, ?, ?)",
                    (salt, pin_hash, question, answer_hash)
                )
                conn.commit()
            lock_folder()
            close_dialog()
            navigator()
        bs.title=ft.Text("Set PIN & Security Question", size=18)
        bs.content=ft.Column([pin_field, question_field, answer_field], tight=True)
        bs.actions=[ft.TextButton("Submit", on_click=set_initial_password),ft.TextButton("Cancel", on_click=lambda e: close_dialog())]
        page.open(bs)
        page.update()
    def show_login_dialog():
        pin_input = ft.TextField(label="Enter 4-digit PIN", password=True, can_reveal_password=True,
                                 max_length=4, autofocus=True, keyboard_type=ft.KeyboardType.NUMBER,
                                 input_filter=ft.InputFilter(allow=True, regex_string=r"^\d*$"))
        def validate_pin(e):
            if len(pin_input.value) == 4:
                pin = pin_input.value.strip()
                salt, pin_hash, *_ = stored
                if hmac.compare_digest(hash_value(pin, salt), pin_hash):
                    close_dialog()
                    navigator()
                else:
                    pin_input.error_text = "Invalid PIN"
                    page.update()
        pin_input.on_change = validate_pin
        bs.title=ft.Row([
            ft.Text("Enter PIN", size=20),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, on_click=lambda e: close_dialog())
        ])
        bs.content=pin_input
        bs.actions=[ft.TextButton("Forgot Password?", on_click=lambda e: show_question_dialog())]
        page.open(bs)
        page.update()
    if not stored:
        show_initial_setup_dialog()
    else:
        show_login_dialog()