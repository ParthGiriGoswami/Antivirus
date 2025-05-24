import flet as ft
from Screen.Helper import lock_folder,unlock_folder
from Screen.ScanDir import scan_directory
def listfiles(page, idp,exclusion=None,path=None,file=None):
    ITEMS_PER_PAGE = 500
    current_page = [0]
    all_files = [sorted(path)]
    total_files = [len(all_files[0])]
    selected_files_dict = {f: False for f in all_files[0]}
    file_list_height = 150 if idp == "Result" else 430
    file_list = ft.ListView(controls=[], spacing=10, padding=10, auto_scroll=False, height=file_list_height)
    page_label = ft.Text()
    add_button = ft.TextButton("Add to exclusion list", disabled=True)
    remove_button = ft.TextButton("Remove", disabled=True)
    prev_button = ft.ElevatedButton("Previous")
    next_button = ft.ElevatedButton("Next")
    remove = ft.TextButton(f"Remove From {idp}", disabled=True)
    select_all_button = ft.TextButton("Select All")
    icon = ft.Icon(ft.Icons.CLOSE, color=ft.Colors.RED, size=200) if idp == "Result" else None
    files = ft.Text(f"{len(path)} files found", size=20) if idp == "Result" else None
    def update_remove_button_state():
        any_selected = any(selected_files_dict.values())
        remove.disabled = not any_selected
        add_button.disabled = not any_selected
        remove_button.disabled = not any_selected
        page.update()
    def on_checkbox_change(e, file_path):
        selected_files_dict[file_path] = e.control.value
        update_remove_button_state()
    def refresh_checkbox_list():
        total_files[0] = len(all_files[0])
        start = current_page[0] * ITEMS_PER_PAGE
        end = min((current_page[0] + 1) * ITEMS_PER_PAGE, total_files[0])
        file_list.controls.clear()
        for f in all_files[0][start:end]:
            file_list.controls.append(
                ft.Checkbox(label=f, value=selected_files_dict.get(f, False),on_change=lambda e, f=f: on_checkbox_change(e, f)))
        if total_files[0] > 100:
            any_unchecked = any(not selected_files_dict.get(f, False) for f in all_files[0][start:end])
            select_all_button.text = "Select All" if any_unchecked else "Deselect All"
        page_label.value = f"Page {current_page[0]+1}/{(total_files[0]-1)//ITEMS_PER_PAGE + 1 if total_files[0] else 1}"
        update_pagination_buttons()
        page.update()
    def update_pagination_buttons():
        if idp == "Result" and total_files[0] == 0:
            icon.name, icon.color, icon.size = ft.Icons.CHECK, ft.Colors.GREEN_400, 200
            files.value = "Scan Completed\nNo malware found"
            file_list.visible = False
            bs.actions = []
        elif idp == "Result":
            files.value = f"{total_files[0]} files found"
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
        file_path = "files/exclusion.txt" if idp == "Exclusion List" else "files/quickpath.txt"
        unlock_folder()
        with open(file_path, "w") as f:
            for line in path:
                f.write(f"{line}\n")
        lock_folder()
        if idp == "Exclusion List" and exclusion is not None:
            exclusion.clear()
            exclusion.update(path)
        if idp == "Quick List":
            file.clear()
            file.update(scan_directory(dir_path, set()) for dir_path in path)
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
            with open("files/exclusion.txt", "r") as f:
                existing_paths = set(line.strip() for line in f.readlines())
        except FileNotFoundError:
            pass
        finally:
            lock_folder()
        updated_paths = existing_paths.union(selected)
        unlock_folder()
        exclusion.clear()
        exclusion.update(updated_paths)
        with open("files/exclusion.txt", "w") as f:
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
    def remove_files(e):
        selected = {f for f, v in selected_files_dict.items() if v}
        if not selected:
            return
        nonlocal path
        path -= selected
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        for f in all_files[0]:
            selected_files_dict[f] = False
        current_page[0] = 0
        refresh_checkbox_list()
    def add_file_result(e):
        if e.files:
            for f in e.files:
                path.add(f.path)
        unlock_folder()
        with open("files/exclusion.txt", "w") as f:
            for line in path:
                f.write(f"{line}\n")
        lock_folder()
        exclusion.clear()
        exclusion.update(path)
        all_files[0] = sorted(path)
        selected_files_dict.clear()
        for f in all_files[0]:
            selected_files_dict[f] = False
        refresh_checkbox_list()
    def add_folder_result(e):
        if e.path:
            path.add(e.path)
            unlock_folder()
            with open("files/quickpath.txt", "w") as f:
                for line in path:
                    f.write(f"{line}\n")
            lock_folder()
            file.clear()
            file.update(scan_directory(dir_path, set()) for dir_path in path)
            all_files[0] = sorted(path)
            selected_files_dict.clear()
            for f in all_files[0]:
                selected_files_dict[f] = False
            refresh_checkbox_list()
    def add(e):
        if idp == "Exclusion List":
            file_picker.pick_files(allow_multiple=True)
        else:
            folder_picker.get_directory_path()
    def close_bs(e):
        page.close(bs)
        page.update()
    add_button.on_click = add_to_exclusion_list
    remove_button.on_click = remove_files
    remove.on_click = remove_selected_files
    prev_button.on_click = prev_page
    next_button.on_click = next_page
    select_all_button.on_click = toggle_select_all
    file_picker = ft.FilePicker(on_result=add_file_result)
    folder_picker = ft.FilePicker(on_result=add_folder_result)
    page.overlay.extend([file_picker, folder_picker])
    if len(path) == 0 and idp == "Result":
        content_column = ft.Column([
            ft.Icon(ft.Icons.CHECK, color=ft.Colors.GREEN_400, size=200),
            ft.Text("Scan Completed", size=20),
            ft.Text("No malware found")
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        actions = []
    else:
        column_controls = []
        if icon: column_controls.append(icon)
        if files: column_controls.append(files)
        column_controls.append(file_list)
        column_controls.append(ft.Row([prev_button, page_label, next_button]))
        content_column = ft.Column(column_controls,
                                   alignment=ft.MainAxisAlignment.CENTER,
                                   horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        actions = [select_all_button, add_button, remove_button] if idp == "Result" else [remove, select_all_button, ft.TextButton("Add", on_click=add)]

    cont = ft.Container(width=page.width, height=500, content=content_column)
    bs = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Text(idp, size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.CLOSE, tooltip="Close", on_click=close_bs)
        ]),
        content=cont,
        actions=actions,
        actions_alignment=ft.CrossAxisAlignment.END
    )
    refresh_checkbox_list()
    page.open(bs)
    page.update()