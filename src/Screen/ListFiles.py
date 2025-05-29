import flet as ft,os,json,shutil,sqlite3
from datetime import datetime
from Screen.Helper import lock_folder, unlock_folder
from Screen.ScanDir import scan_directory
def listfiles(page, VAULT_DIR, idp, exclusion=None, path=None, file=None, back_cont=None, quarantine=None):
    bs = ft.AlertDialog(modal=True)
    ITEMS_PER_PAGE = 500
    current_page = [0]
    if path is None:
        path = set()
    all_files = [sorted(path)]
    total_files = [len(all_files[0])]
    selected_files_dict = {f: False for f in all_files[0]}
    use_table = (idp == "Pendrive list" or idp == "Quarantine folder")
    if use_table:
        if(idp== "Pendrive list"):
            data_table = ft.DataTable(
                columns=[ft.DataColumn(ft.Text("ID")),ft.DataColumn(ft.Text("Path"))],
                rows=[],
            )
        else:
            data_table = ft.DataTable(
                columns=[
                    ft.DataColumn(ft.Text("File name")),ft.DataColumn(ft.Text("Original Path")),ft.DataColumn(ft.Text("New Path")),ft.DataColumn(ft.Text("Timestamp"))
                ],
                rows=[],
            )
        file_list = ft.Container(content=data_table)
    else:
        data_table = None
        file_list = ft.ListView(controls=[], spacing=10, padding=10, auto_scroll=False, expand=True)
    page_label = ft.Text()
    add_button = ft.TextButton("Add to exclusion list", disabled=True)
    remove_button = ft.TextButton("Remove", disabled=True)
    prev_button = ft.ElevatedButton("Previous")
    next_button = ft.ElevatedButton("Next")
    info = ft.TextButton("")
    remove = ft.TextButton(f"Remove From {idp}", disabled=True)
    select_all_button = ft.TextButton("Select All")
    icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=200) if idp == "Result" else None
    files_label = ft.Text(f"{len(path)} files found") if idp == "Result" else None
    restore= ft.TextButton("Restore", disabled=True)
    def close_bs(e):
        page.close(bs)
        page.update()
    def back(e):
        bs.title = ft.Row([
            ft.Text("Edit Files", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs)
        ])
        bs.content = ft.Container(width=page.width, height=500, content=back_cont)
        bs.actions = None
        page.update()
    def update_remove_button_state():
        any_selected = any(selected_files_dict.values())
        remove.disabled = add_button.disabled = remove_button.disabled = restore.disabled = not any_selected
        page.update()
    def on_checkbox_change(e, file_path):
        selected_files_dict[file_path] = e.control.value
        update_remove_button_state()
    def refresh_checkbox_list():
        total_files[0] = len(all_files[0])
        start = current_page[0] * ITEMS_PER_PAGE
        end = min((current_page[0] + 1) * ITEMS_PER_PAGE, total_files[0])
        if use_table:
            data_table.rows.clear()
            for i, f in enumerate(all_files[0][start:end], start=start):
                checkbox = ft.Checkbox(
                    value=selected_files_dict.get(f, False),
                    on_change=lambda e, f=f: on_checkbox_change(e, f)
                )
                if idp=="Pendrive list":
                    data_table.rows.append(ft.DataRow(cells=[ft.DataCell(ft.Row([checkbox, ft.Text(f[0])])),ft.DataCell(ft.Text(f[1]))]))
                    file_list.expand=True
                else:
                    data_table.rows.append(ft.DataRow(cells=[ft.DataCell(ft.Row([checkbox, ft.Text(f[0],overflow="ellipsis",width=200)])),ft.DataCell(ft.Text(f[1],overflow="ellipsis",width=200)),ft.DataCell(ft.Text(f[2],overflow="ellipsis",width=200)),ft.DataCell(ft.Text(f[3],overflow="ellipsis",width=200))]))
        else:
            file_list.controls.clear()
            for f in all_files[0][start:end]:
                file_list.controls.append(
                    ft.Checkbox(
                        label=f,
                        value=selected_files_dict.get(f, False),
                        on_change=lambda e, f=f: on_checkbox_change(e, f)
                    )
                )
        if total_files[0] > 100:
            any_unchecked = any(not selected_files_dict.get(f, False) for f in all_files[0][start:end])
            select_all_button.text = "Select All" if any_unchecked else "Deselect All"
        page_label.value = f"Page {current_page[0] + 1}/{(total_files[0] - 1) // ITEMS_PER_PAGE + 1 if total_files[0] else 1}"
        update_pagination_buttons()
        page.update()
    def update_pagination_buttons():
        if idp == "Result" and total_files[0] == 0:
            bs.content = ft.Container(
                width=page.width,
                height=500,
                content=ft.Column([
                    ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200),
                    ft.Text("Scan Completed", weight=ft.FontWeight.BOLD, size=20),
                    ft.Text("No malware found")
                ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
            )
            bs.actions = []
        elif idp == "Result":
            files_label.value = f"{total_files[0]} files found"
        prev_button.disabled = current_page[0] == 0
        next_button.disabled = (current_page[0] + 1) * ITEMS_PER_PAGE >= total_files[0]
        page_label.visible = prev_button.visible = next_button.visible = total_files[0] > ITEMS_PER_PAGE
        update_remove_button_state()
    def next_page(e):
        if (current_page[0] + 1) * ITEMS_PER_PAGE < total_files[0]:
            current_page[0] += 1
            refresh_checkbox_list()
    def prev_page(e):
        if current_page[0] > 0:
            current_page[0] -= 1
            refresh_checkbox_list()
    def toggle_select_all(e):
        start = current_page[0] * ITEMS_PER_PAGE
        end = min((current_page[0] + 1) * ITEMS_PER_PAGE, total_files[0])
        all_checked = all(selected_files_dict.get(f, False) for f in all_files[0][start:end])
        for f in all_files[0][start:end]:
            selected_files_dict[f] = not all_checked
        refresh_checkbox_list()
    def remove_selected_files(e):
        nonlocal path
        selected = {f for f, v in selected_files_dict.items() if v}
        path -= selected
        unlock_folder()
        if idp == "Pendrive list":
            with open(f"{VAULT_DIR}/exclusion.json", "w") as f:
                json.dump(sorted(path), f, indent=4)
        elif idp == "Quarantine folder":
            db_path = os.path.join(VAULT_DIR, "quarantine.db")
            for entry in selected:
                filename, original_path, quarantine_path, timestamp = entry
                os.remove(quarantine_path)
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM quarantine WHERE filename = ?", (filename,))
                    conn.commit()
        else:
            file_path = f"{VAULT_DIR}/exclusion.txt" if idp == "Exclusion List" else f"{VAULT_DIR}/quickpath.txt"
            with open(file_path, "w") as f:
                for line in path:
                    f.write(f"{line}\n")
        lock_folder()
        if idp == "Quick List" and file is not None:
            file.clear()
            file.update(set().union(*(scan_directory(dir_path, set()) for dir_path in path)))
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def add_to_exclusion_list(e):
        selected = {f for f, v in selected_files_dict.items() if v}
        if not selected:
            return
        existing_paths = set()
        try:
            unlock_folder()
            with open(f"{VAULT_DIR}/exclusion.txt", "r") as f:
                existing_paths = set(line.strip() for line in f.readlines())
        except FileNotFoundError:
            pass
        finally:
            lock_folder()
        updated_paths = existing_paths.union(selected)
        unlock_folder()
        exclusion.clear()
        exclusion.update(updated_paths)
        with open(f"{VAULT_DIR}/exclusion.txt", "w") as f:
            for line in sorted(updated_paths):
                f.write(f"{line}\n")
        lock_folder()
        if idp == "Result":
            nonlocal path
            path -= selected
            all_files[0] = sorted(path)
            selected_files_dict.clear()
            for f in all_files[0]:
                selected_files_dict[f] = False
            current_page[0] = 0
            refresh_checkbox_list()
    def quarantine_file(file_path, VAULT_DIR):
        try:
            unlock_folder()
            db_path = os.path.join(VAULT_DIR, "quarantine.db")
            quarantine_dir = os.path.join(VAULT_DIR, "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            basename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, basename)
            counter = 1
            base_name, ext = os.path.splitext(basename)
            while os.path.exists(quarantine_path):
                quarantine_path = os.path.join(quarantine_dir, f"{base_name}_{counter}{ext}")
                counter += 1
            shutil.move(file_path, quarantine_path)
            timestamp = datetime.now().isoformat()
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO quarantine (filename, original_path, quarantine_path, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (basename, file_path, quarantine_path, timestamp))
                conn.commit()
            if quarantine is not None:
                quarantine.add((basename, file_path, quarantine_path, timestamp))
            else:
                path.add((basename, file_path, quarantine_path, timestamp))
            lock_folder()
            return True
        except:
            return False
    def remove_files(e):
        selected = {f for f, v in selected_files_dict.items() if v}
        if not selected:
            return
        nonlocal path
        for file_path in selected:
            if not quarantine_file(file_path, VAULT_DIR):
                lock_folder()
                with open(f"{VAULT_DIR}/exclusion.txt", "a") as f:
                    f.write(f"{file_path}\n")
                unlock_folder()
        path -= selected
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def add_file_result(e):
        if idp == "Exclusion List":
            if e.files:
                for f in e.files:
                    path.add(f.path)
            unlock_folder()
            with open(f"{VAULT_DIR}/exclusion.txt", "w") as f:
                for line in path:
                    f.write(f"{line}\n")
            lock_folder()
            all_files[0] = sorted(path)
            selected_files_dict.clear()
            for f in all_files[0]:
                selected_files_dict[f] = False
            refresh_checkbox_list()
        else:
            if e.files:
                for f in e.files:
                    quarantine_file(f.path, VAULT_DIR)
            all_files[0] = sorted(path)
            selected_files_dict.clear()
            for f in all_files[0]:
                selected_files_dict[f] = False
            refresh_checkbox_list()
    def restore_files(e):
        nonlocal path
        selected = {f for f, v in selected_files_dict.items() if v}
        if not selected:
            return
        unlock_folder()
        db_path = os.path.join(VAULT_DIR, "quarantine.db")
        for entry in selected:
            filename, original_path, quarantine_path, timestamp = entry
            shutil.move(quarantine_path, original_path)
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM quarantine WHERE filename = ?", (filename,))
                conn.commit()
        lock_folder()
        path -= selected
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        selected_files_dict.update({f: False for f in all_files[0]})
        current_page[0] = 0
        refresh_checkbox_list()
    def add_folder_result(e):
        if e.path:
            path.add(e.path)
            unlock_folder()
            with open(f"{VAULT_DIR}/quickpath.txt", "w") as f:
                for line in path:
                    f.write(f"{line}\n")
            lock_folder()
            if file is not None:
                file.clear()
                file.update(set().union(*(scan_directory(dir_path, set()) for dir_path in path)))
            all_files[0] = sorted(path)
            selected_files_dict.clear()
            for f in all_files[0]:
                selected_files_dict[f] = False
            refresh_checkbox_list()
    def add(e):
        if idp == "Exclusion List" or idp== "Quarantine folder":
            file_picker.pick_files(allow_multiple=True)
        else:
            folder_picker.get_directory_path()
    add_button.on_click = add_to_exclusion_list
    remove_button.on_click = remove_files
    remove.on_click = remove_selected_files
    restore.on_click = restore_files
    prev_button.on_click = prev_page
    next_button.on_click = next_page
    select_all_button.on_click = toggle_select_all
    file_picker = ft.FilePicker(on_result=add_file_result)
    folder_picker = ft.FilePicker(on_result=add_folder_result)
    page.overlay.extend([file_picker, folder_picker])
    if len(path) == 0 and idp == "Result":
        bs.content = ft.Container(
            width=page.width,
            height=500,
            content=ft.Column([
                ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200),
                ft.Text("Scan Completed", weight=ft.FontWeight.BOLD, size=20),
                ft.Text("No malware found")
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        )
        bs.actions = []
    else:
        add_btn = ft.TextButton("Add", on_click=add) if idp != "Pendrive list" else None
        column_controls = [c for c in [icon, files_label, file_list, info, ft.Row([prev_button, page_label, next_button])] if c]
        bs.actions = [select_all_button, add_button, remove_button] if idp == "Result" else [restore, remove, select_all_button, add_btn] if idp == "Quarantine folder" else [btn for btn in [remove, select_all_button, add_btn] if btn is not None]
        bs.content = ft.Container(
            width=page.width,
            height=500,
            content=ft.Column(
                column_controls,
                expand=True,
                alignment=ft.MainAxisAlignment.START,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH
            )
        )
    back_btn = None if back_cont is None else ft.IconButton(icon=ft.Icons.ARROW_BACK,on_click= back)
    bs.title = ft.Row([
        *([back_btn] if back_btn is not None else []),
        ft.Text(idp, size=20, weight=ft.FontWeight.BOLD),
        ft.Container(expand=True),
        ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs)
    ])
    refresh_checkbox_list()
    page.open(bs)
    page.update()