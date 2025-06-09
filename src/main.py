import flet as ft,os,sys
from Screen.Mainpage import MainPage
def main(page: ft.Page):
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(
        color_scheme=ft.ColorScheme(
            primary=ft.Colors.BLUE_200,secondary=ft.Colors.BLUE_GREY,
            surface=ft.Colors.BLACK,background="#121212",
            on_surface=ft.Colors.WHITE,on_primary=ft.Colors.WHITE,
        ))
    def resource_path(relative_path):
        base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
        return os.path.join(base_path, relative_path)
    if os.name == "nt":
        icon_path = resource_path("src/assets/icon.ico")
    else:
        icon_path = resource_path("src/assets/icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    page.window.icon = icon_path
    page.title = "Kepler Antivirus"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    def route_change(route):
        page.views.clear()  
        if page.route == "/home":
            view=MainPage(page)
            page.views.append(view)
        page.update()
    page.on_route_change = route_change
    page.go("/home")
ft.app(target=main)