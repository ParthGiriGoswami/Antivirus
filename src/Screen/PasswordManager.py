import flet as ft
import re, os, pickle, asyncio
from cryptography.fernet import Fernet
from Screen.Helper import lock_folder, unlock_folder
def load_or_create_key():
    os.makedirs("{VAULT_DIR}", exist_ok=True)
    key_path =r"{VAULT_DIR}/.datastore.bin"
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
    else:
        with open(key_path, "rb") as f:
            key = f.read()
    return key
fernet = Fernet(load_or_create_key())
def encrypt(data):
    return fernet.encrypt(data.encode()).decode()
def decrypt(token):
    return fernet.decrypt(token.encode()).decode()
def passwordmanager(page: ft.Page,VAULT_DIR):
    auto_close_task = None
    def close_bs(e=None):
        nonlocal auto_close_task
        if auto_close_task and not auto_close_task.done():
            auto_close_task.cancel()
        bs.open = False
        page.update()
    async def auto_close_dialog():
        try:
            await asyncio.sleep(300)
            bs.open = False
            page.snack_bar = ft.SnackBar(ft.Text("Session expired", color=ft.Colors.WHITE), bgcolor="#272A2F")
            page.snack_bar.open = True
            page.update()
        except:
            pass
    auto_close_task = page.run_task(auto_close_dialog)
    def add_new_password(e):
        form.visible = not form.visible
        add_button.icon = ft.Icons.REMOVE if form.visible else ft.Icons.ADD
        cont.height = 300 if form.visible else 500
        page.update()
    def is_site_format_valid(site_value):
        pattern = r"^(http:\/\/|https:\/\/)?[a-zA-Z0-9\-]+(\.com)$"
        return not site_value or re.match(pattern, site_value.strip())
    def validate_site(e):
        site.error_text = "Invalid site format" if not is_site_format_valid(site.value) else None
        enable_disable_save_button()
        page.update()
    def on_change(e):
        enable_disable_save_button()
        page.update()
    def load_data():
        filepath =r"{VAULT_DIR}/passwords.txt"
        try:
            unlock_folder()
            with open(filepath, "rb") as f:
                return pickle.load(f)
        except (FileNotFoundError, pickle.UnpicklingError):
            return {}
        finally:
            lock_folder()
    def save_data(data):
        unlock_folder()
        os.makedirs(r"{VAULT_DIR}", exist_ok=True)
        with open(r"{VAULT_DIR}/passwords.txt", "wb") as f:
            pickle.dump(data, f)
        lock_folder()
    def save_password(e):
        site_key = site.value.strip()
        new_entry = {
            "username": encrypt(username.value),
            "password": encrypt(password.value)
        }
        all_data = load_data()
        all_data.setdefault(site_key, []).append(new_entry)
        save_data(all_data)
        site.value = username.value = password.value = ""
        load_passwords_view()
        enable_disable_save_button()
        page.update()
    def enable_disable_save_button():
        save_button.disabled = not (
            site.value and username.value and password.value and is_site_format_valid(site.value)
        )
    def load_passwords_view():
        def create_credential_row(entry, site_name, entry_index):
            try:
                original_username = decrypt(entry["username"])
                original_password = decrypt(entry["password"])
            except Exception:
                original_username = "<decryption error>"
                original_password = "<decryption error>"

            user = ft.TextField(
                label="Username",
                value=original_username,
                read_only=True,
                suffix=ft.IconButton(
                    icon=ft.Icons.CONTENT_COPY,
                    on_click=lambda e, val=original_username: page.set_clipboard(val),
                    icon_size=18,
                    style=ft.ButtonStyle(padding=0),
                ),
            )
            passw = ft.TextField(
                label="Password",
                value=original_password,
                read_only=True,
                password=True,
                can_reveal_password=True,
                suffix=ft.IconButton(
                    icon=ft.Icons.CONTENT_COPY,
                    on_click=lambda e, val=original_password: page.set_clipboard(val),
                    icon_size=18,
                    style=ft.ButtonStyle(padding=0),
                ),
            )
            edit_btn = ft.TextButton()
            del_btn = ft.TextButton()
            def cancel_edit(e):
                user.value = original_username
                passw.value = original_password
                toggle_edit(e)
            def save_edit(e):
                all_data = load_data()
                if site_name in all_data and len(all_data[site_name]) > entry_index:
                    all_data[site_name][entry_index] = {
                        "username": encrypt(user.value),
                        "password": encrypt(passw.value)
                    }
                    save_data(all_data)
                toggle_edit(e)
            def toggle_edit(e):
                is_editing = user.read_only
                user.read_only = not is_editing
                passw.read_only = not is_editing
                edit_btn.text = "Save" if is_editing else "Edit"
                del_btn.text = "Cancel" if is_editing else "Delete"
                edit_btn.on_click = save_edit if is_editing else toggle_edit
                del_btn.on_click = cancel_edit if is_editing else delete_entry
                page.update()
            def delete_entry(e):
                all_data = load_data()
                if site_name in all_data and len(all_data[site_name]) > entry_index:
                    del all_data[site_name][entry_index]
                    if not all_data[site_name]:
                        del all_data[site_name]
                    save_data(all_data)
                    load_passwords_view()
            edit_btn.text = "Edit"
            del_btn.text = "Delete"
            edit_btn.on_click = toggle_edit
            del_btn.on_click = delete_entry
            return ft.Column([
                user,
                passw,
                ft.Row([edit_btn, del_btn], alignment=ft.MainAxisAlignment.END),
                ft.Divider()
            ])
        list_items = []
        data = load_data()
        for site_name, credentials in data.items():
            expanded = ft.Column(visible=False)
            for i, entry in enumerate(credentials):
                expanded.controls.append(create_credential_row(entry, site_name, i))
            arrow_icon = ft.Icon(name=ft.Icons.KEYBOARD_ARROW_DOWN)
            def create_expand_toggle(section, icon):
                def toggle(e):
                    section.visible = not section.visible
                    icon.name = ft.Icons.KEYBOARD_ARROW_UP if section.visible else ft.Icons.KEYBOARD_ARROW_DOWN
                    page.update()
                return toggle
            site_row = ft.Container(
                on_click=create_expand_toggle(expanded, arrow_icon),
                padding=8,
                bgcolor=ft.Colors.BLACK12,
                content=ft.Row([
                    ft.Text(site_name, size=16, weight=ft.FontWeight.BOLD),
                    arrow_icon
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            )
            list_items.append(ft.Column([site_row, expanded]))
        cont.content = ft.ListView(controls=list_items, expand=True, spacing=10, padding=8)
        page.update()
    site = ft.TextField(label="Site", hint_text="example.com", on_blur=validate_site, on_change=on_change)
    username = ft.TextField(label="Username", on_change=on_change)
    password = ft.TextField(label="Password", password=True, on_change=on_change)
    save_button = ft.ElevatedButton("Save", disabled=True, on_click=save_password)
    form = ft.Container(
        content=ft.Column([
            site, username, password,
            ft.Row([save_button], alignment=ft.MainAxisAlignment.END)
        ]),
        visible=False
    )
    cont = ft.Container(
        width=page.width,
        height=500,
        content=ft.ListView(controls=[], spacing=10, padding=10, auto_scroll=False, expand=True)
    )
    add_button = ft.IconButton(icon=ft.Icons.ADD, tooltip="Add", on_click=add_new_password)
    bs = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Text("Password", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            add_button,
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs),
        ], alignment=ft.MainAxisAlignment.START),
        actions_alignment=ft.CrossAxisAlignment.END,
        content=ft.Column([form, ft.Divider(), cont])
    )
    page.open(bs)
    load_passwords_view()
    page.update()