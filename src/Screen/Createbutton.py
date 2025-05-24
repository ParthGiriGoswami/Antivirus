import flet as ft
def create_custom_button(page,label, description,icon=None,on_click=None,h=105):
    return ft.TextButton(
        content=ft.Row(
            [
                ft.Container(
                    content=ft.Icon(icon,size=100,color=ft.Colors.WHITE),
                    alignment=ft.alignment.center_left,
                    width=100,
                ),
                ft.Column(
                    [
                        ft.Text(value=label, size=30,color=ft.Colors.WHITE),
                        ft.Text(value=description,color=ft.Colors.WHITE),
                    ],
                    alignment=ft.MainAxisAlignment.START,
                ),
            ],
            alignment=ft.MainAxisAlignment.START,
        ),
        on_click=on_click,
        adaptive=True,
        height=h,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=8),
            alignment=ft.alignment.center,
            bgcolor=ft.Colors.BLUE_ACCENT_700
        ),
    )