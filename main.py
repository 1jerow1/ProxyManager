from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from ctypes import wintypes

import customtkinter as ctk
import pystray
import requests
from PIL import Image, ImageDraw


BASE_DIR = Path(__file__).resolve().parent
BIN_PATH = BASE_DIR / "bin" / "sing-box.exe"
CONFIG_DIR = BASE_DIR / "configs"
CONFIG_PATH = CONFIG_DIR / "proxy.json"
SETTINGS_PATH = BASE_DIR / "settings.json"
LOG_DIR = BASE_DIR / "logs"
LOG_PATH = LOG_DIR / "sing-box.log"
PID_PATH = LOG_DIR / "sing-box.pid"

DEFAULT_SETTINGS = {
    "proxy_type": "socks",
    "profiles": {
        "socks": {
            "host": "",
            "port": 1080,
            "username": "",
            "password": ""
        },
        "http": {
            "host": "",
            "port": 1080,
            "username": "",
            "password": ""
        }
    }
}


def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)


def load_settings() -> dict[str, Any]:
    if not SETTINGS_PATH.exists():
        return json.loads(json.dumps(DEFAULT_SETTINGS))
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        proxy_type = data.get("proxy_type", DEFAULT_SETTINGS["proxy_type"])
        if proxy_type not in {"socks", "http"}:
            proxy_type = DEFAULT_SETTINGS["proxy_type"]

        profiles = json.loads(json.dumps(DEFAULT_SETTINGS["profiles"]))
        saved_profiles = data.get("profiles")
        if isinstance(saved_profiles, dict):
            for kind in ("socks", "http"):
                profile = saved_profiles.get(kind)
                if isinstance(profile, dict):
                    profiles[kind].update(profile)
        else:
            legacy_profile = {
                key: data[key]
                for key in ("host", "port", "username", "password")
                if key in data
            }
            profiles[proxy_type].update(legacy_profile)

        return {"proxy_type": proxy_type, "profiles": profiles}
    except (OSError, json.JSONDecodeError):
        return json.loads(json.dumps(DEFAULT_SETTINGS))


def save_settings(data: dict[str, Any]) -> None:
    # For this starter project the credentials are stored locally in settings.json.
    # Restrict access to this file to your Windows account before using it on a shared PC.
    SETTINGS_PATH.write_text(
        json.dumps(data, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    # Re-launch the current Python interpreter with the current script.
    params = subprocess.list2cmdline([str(Path(__file__).resolve())])
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, str(BASE_DIR), 1
    )
    if result <= 32:
        raise RuntimeError("Не удалось получить права администратора.")
    raise SystemExit(0)


def acquire_single_instance_mutex() -> int | None:
    ctypes.windll.kernel32.SetLastError(0)
    mutex = ctypes.windll.kernel32.CreateMutexW(
        None, False, "Local\\ProxyManagerWindowsSingleInstance"
    )
    if not mutex:
        raise OSError("Не удалось создать системную блокировку экземпляра.")
    if ctypes.windll.kernel32.GetLastError() == 183:
        ctypes.windll.kernel32.CloseHandle(mutex)
        return None
    return int(mutex)


class ProxyManager:
    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.log_handle = None
        self.lock = threading.Lock()

    def is_running(self) -> bool:
        if self.process is not None and self.process.poll() is None:
            return True
        return self._tracked_pid() is not None

    def _tracked_pid(self) -> int | None:
        try:
            pid = int(PID_PATH.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None
        return pid if pid > 0 else None

    @staticmethod
    def _process_matches_binary(pid: int) -> bool:
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD)
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            image_path = ctypes.create_unicode_buffer(32768)
            path_length = wintypes.DWORD(len(image_path))
            if not kernel32.QueryFullProcessImageNameW(
                handle, 0, image_path, ctypes.byref(path_length)
            ):
                return False
            return Path(image_path.value).resolve() == BIN_PATH.resolve()
        finally:
            kernel32.CloseHandle(handle)

    def _remove_pid_file(self, pid: int | None = None) -> None:
        if pid is not None and self._tracked_pid() != pid:
            return
        PID_PATH.unlink(missing_ok=True)

    def build_config(self, data: dict[str, Any]) -> dict[str, Any]:
        proxy_type = data.get("proxy_type", "socks")
        if proxy_type not in {"socks", "http"}:
            raise ValueError("Тип прокси должен быть SOCKS5 или HTTP.")

        outbound: dict[str, Any] = {
            "type": proxy_type,
            "tag": "proxy",
            "server": data["host"],
            "server_port": int(data["port"]),
        }
        if proxy_type == "socks":
            outbound["version"] = "5"
        if data.get("username"):
            outbound["username"] = data["username"]
        if data.get("password"):
            outbound["password"] = data["password"]

        dns_server = {
            "type": "https" if proxy_type == "http" else "udp",
            "tag": "dns-remote",
            "server": "1.1.1.1",
            "server_port": 443 if proxy_type == "http" else 53,
            "detour": "proxy"
        }
        if proxy_type == "http":
            dns_server["path"] = "/dns-query"

        route: dict[str, Any] = {
            "auto_detect_interface": True,
            "final": "proxy"
        }
        if proxy_type == "http":
            route["rules"] = [
                {
                    "ip_version": 6,
                    "action": "reject"
                },
                {
                    "network": "udp",
                    "action": "reject"
                }
            ]

        dns_config: dict[str, Any] = {
            "servers": [dns_server],
            "final": "dns-remote"
        }
        if proxy_type == "http":
            dns_config["strategy"] = "ipv4_only"

        return {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "dns": dns_config,
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "singbox",
                    "address": [
                        "172.19.0.1/30",
                        "fdfe:dcba:9876::1/126"
                    ],
                    "auto_route": True,
                    "strict_route": True
                }
            ],
            "outbounds": [outbound],
            "route": route
        }

    def write_config(self, data: dict[str, Any]) -> None:
        config = self.build_config(data)
        CONFIG_PATH.write_text(
            json.dumps(config, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

    def connect(self, data: dict[str, Any]) -> tuple[bool, str]:
        with self.lock:
            if self.is_running():
                return False, "Прокси уже подключён."
            if not BIN_PATH.is_file():
                return False, (
                    "Не найден bin\\sing-box.exe. Скачайте Windows amd64 "
                    "версию sing-box и положите sing-box.exe в папку bin."
                )

            try:
                self.write_config(data)
                check = subprocess.run(
                    [str(BIN_PATH), "check", "-c", str(CONFIG_PATH)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    cwd=str(BASE_DIR),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                if check.returncode != 0:
                    detail = (check.stderr or check.stdout or "Неизвестная ошибка").strip()
                    return False, f"Ошибка конфигурации sing-box:\n{detail}"

                self.log_handle = open(LOG_PATH, "a", encoding="utf-8")
                self.process = subprocess.Popen(
                    [str(BIN_PATH), "run", "-c", str(CONFIG_PATH)],
                    stdout=self.log_handle,
                    stderr=subprocess.STDOUT,
                    cwd=str(BASE_DIR),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                PID_PATH.write_text(str(self.process.pid), encoding="ascii")

                time.sleep(1.2)
                if self.process.poll() is not None:
                    self._remove_pid_file(self.process.pid)
                    self.process = None
                    self._close_log()
                    try:
                        details = LOG_PATH.read_text(encoding="utf-8")[-2500:]
                    except OSError:
                        details = ""
                    return False, "sing-box не запустился.\n" + details

                return True, "Команда подключения запущена. Проверяем внешний IP."
            except subprocess.TimeoutExpired:
                return False, "Проверка конфигурации заняла слишком много времени."
            except Exception as exc:
                if self.process is not None and self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=5)
                    self._remove_pid_file(self.process.pid)
                    self.process = None
                self._close_log()
                return False, f"Не удалось запустить sing-box: {exc}"

    def _close_log(self) -> None:
        if self.log_handle:
            try:
                self.log_handle.close()
            except Exception:
                pass
            self.log_handle = None

    def disconnect(self) -> tuple[bool, str]:
        with self.lock:
            try:
                if self.process is not None:
                    pid = self.process.pid
                    if self.process.poll() is None:
                        try:
                            self.process.terminate()
                            self.process.wait(timeout=8)
                        except (OSError, subprocess.TimeoutExpired):
                            self._force_stop(pid)
                            self.process.wait(timeout=5)
                    self._remove_pid_file(pid)
                    self.process = None
                    self._close_log()
                    return True, "Прокси отключён."

                pid = self._tracked_pid()
                if pid is None:
                    return True, "Прокси уже отключён."
                if not self._process_matches_binary(pid):
                    self._remove_pid_file(pid)
                    return True, "Запущенный sing-box не найден; файл состояния очищен."
                self._force_stop(pid)
                self._remove_pid_file(pid)
                self._close_log()
                return True, "Зависший sing-box остановлен; интернет-маршрут восстановлен."
            except Exception as exc:
                return False, f"Не удалось остановить sing-box: {exc}"

    @staticmethod
    def _force_stop(pid: int) -> None:
        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(detail or f"taskkill завершился с кодом {result.returncode}")


class ProxyApp:
    def __init__(self) -> None:
        ensure_dirs()
        self.manager = ProxyManager()
        self.settings = load_settings()
        self.closing = False
        self.tray: pystray.Icon | None = None

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("Proxy Manager")
        self.root.geometry("460x700")
        self.root.minsize(430, 670)
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)

        proxy_type = self.settings.get("proxy_type", "socks")
        self.proxy_type_var = ctk.StringVar(
            value="HTTP" if proxy_type == "http" else "SOCKS5"
        )
        self.active_proxy_type = proxy_type
        self._build_ui()
        self._show_profile(proxy_type)
        self._start_tray()
        self._refresh_status()
        self.root.mainloop()

    def _build_ui(self) -> None:
        ctk.CTkLabel(
            self.root, text="PROXY MANAGER",
            font=ctk.CTkFont(size=25, weight="bold")
        ).pack(pady=(24, 5))

        ctk.CTkLabel(
            self.root, text="Управление системным интернет-трафиком через прокси",
            text_color="gray", wraplength=390
        ).pack(pady=(0, 18))

        self.status_label = ctk.CTkLabel(
            self.root, text="● Отключено",
            text_color="#ef5350",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.status_label.pack(pady=(0, 12))

        ctk.CTkLabel(self.root, text="Тип прокси", anchor="w").pack(
            fill="x", padx=42, pady=(0, 2)
        )
        ctk.CTkOptionMenu(
            self.root,
            values=["SOCKS5", "HTTP"],
            variable=self.proxy_type_var,
            command=self._on_proxy_type_changed,
            height=36
        ).pack(fill="x", padx=38, pady=(0, 4))

        self.host_entry = self._field("IP-адрес или домен прокси", "")
        self.port_entry = self._field("Порт", "")
        self.user_entry = self._field("Логин", "")
        self.password_entry = self._field("Пароль", "", show="*")

        self.connect_button = ctk.CTkButton(
            self.root, text="ПОДКЛЮЧИТЬ", height=44,
            fg_color="#168b52", hover_color="#116b3e",
            command=self.connect
        )
        self.connect_button.pack(fill="x", padx=38, pady=(22, 8))

        ctk.CTkButton(
            self.root, text="ОТКЛЮЧИТЬ", height=42,
            fg_color="#a83232", hover_color="#842727",
            command=self.disconnect
        ).pack(fill="x", padx=38, pady=5)

        self.ip_label = ctk.CTkLabel(
            self.root, text="Внешний IP: ещё не проверен",
            font=ctk.CTkFont(size=14)
        )
        self.ip_label.pack(pady=(18, 5))

        ctk.CTkButton(
            self.root, text="Проверить внешний IP",
            fg_color="#444b59", hover_color="#343a46",
            command=self.check_ip
        ).pack(pady=5)

        self.message_label = ctk.CTkLabel(
            self.root, text="Окно можно закрыть — программа останется в трее.",
            text_color="gray", wraplength=390
        )
        self.message_label.pack(side="bottom", pady=18)

    def _field(self, title: str, value: str, show: str | None = None) -> ctk.CTkEntry:
        ctk.CTkLabel(self.root, text=title, anchor="w").pack(
            fill="x", padx=42, pady=(6, 2)
        )
        entry = ctk.CTkEntry(self.root, height=36, show=show)
        entry.pack(fill="x", padx=38)
        if value:
            entry.insert(0, value)
        return entry

    def _selected_proxy_type(self) -> str:
        return "http" if self.proxy_type_var.get() == "HTTP" else "socks"

    def _store_current_profile(self, proxy_type: str | None = None) -> None:
        if proxy_type is None:
            proxy_type = self.active_proxy_type
        self.settings["profiles"][proxy_type] = {
            "host": self.host_entry.get().strip(),
            "port": self.port_entry.get().strip(),
            "username": self.user_entry.get().strip(),
            "password": self.password_entry.get()
        }
        self.settings["proxy_type"] = proxy_type

    def _show_profile(self, proxy_type: str) -> None:
        profile = self.settings["profiles"][proxy_type]
        for entry, key in (
            (self.host_entry, "host"),
            (self.port_entry, "port"),
            (self.user_entry, "username"),
            (self.password_entry, "password")
        ):
            entry.delete(0, "end")
            value = profile.get(key, "")
            if value:
                entry.insert(0, str(value))

    def _on_proxy_type_changed(self, value: str) -> None:
        self._store_current_profile(self.active_proxy_type)
        proxy_type = "http" if value == "HTTP" else "socks"
        self.active_proxy_type = proxy_type
        self.settings["proxy_type"] = proxy_type
        self._show_profile(proxy_type)
        save_settings(self.settings)

    def _get_form_data(self) -> dict[str, Any]:
        host = self.host_entry.get().strip()
        if not host:
            raise ValueError("Укажи IP-адрес или домен SOCKS5.")

        try:
            port = int(self.port_entry.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError("Порт должен быть числом от 1 до 65535.")

        return {
            "proxy_type": self._selected_proxy_type(),
            "host": host,
            "port": port,
            "username": self.user_entry.get().strip(),
            "password": self.password_entry.get()
        }

    def connect(self) -> None:
        try:
            data = self._get_form_data()
        except ValueError as exc:
            self._show_message(str(exc))
            return

        self._store_current_profile()
        save_settings(self.settings)
        self.connect_button.configure(state="disabled")
        self.status_label.configure(text="● Запуск...", text_color="#ffb74d")

        def worker() -> None:
            ok, message = self.manager.connect(data)
            self.root.after(0, lambda: self._connection_finished(ok, message))

        threading.Thread(target=worker, daemon=True).start()

    def _connection_finished(self, ok: bool, message: str) -> None:
        self.connect_button.configure(state="normal")
        self._show_message(message)
        self._refresh_status()
        if ok:
            self.check_ip()

    def disconnect(self) -> None:
        ok, message = self.manager.disconnect()
        self._show_message(message)
        self._refresh_status()
        self.ip_label.configure(text="Внешний IP: проверьте подключение")

    def check_ip(self) -> None:
        self.ip_label.configure(text="Внешний IP: проверяем...")

        def worker() -> None:
            try:
                response = requests.get("https://api.ipify.org", timeout=10)
                response.raise_for_status()
                ip = response.text.strip()
                self.root.after(0, lambda: self.ip_label.configure(
                    text=f"Внешний IP: {ip}"
                ))
            except requests.RequestException:
                self.root.after(0, lambda: self.ip_label.configure(
                    text="Не удалось получить внешний IP"
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _show_message(self, message: str) -> None:
        self.message_label.configure(text=message[:500])

    def _refresh_status(self) -> None:
        if self.closing:
            return
        if self.manager.is_running():
            self.status_label.configure(text="● Процесс sing-box запущен", text_color="#22c77a")
        else:
            self.status_label.configure(text="● Отключено", text_color="#ef5350")
        self.root.after(1200, self._refresh_status)

    def _start_tray(self) -> None:
        image = Image.new("RGB", (64, 64), "#172033")
        draw = ImageDraw.Draw(image)
        draw.ellipse((9, 9, 55, 55), fill="#168bdb")
        draw.text((23, 20), "P", fill="white")

        menu = pystray.Menu(
            pystray.MenuItem(
                "Открыть Proxy Manager",
                lambda icon, item: self.root.after(0, self.show_window),
                default=True
            ),
            pystray.MenuItem(
                "Подключить",
                lambda icon, item: self.root.after(0, self.connect)
            ),
            pystray.MenuItem(
                "Отключить",
                lambda icon, item: self.root.after(0, self.disconnect)
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Выход",
                lambda icon, item: self.root.after(0, self.quit_app)
            )
        )

        self.tray = pystray.Icon("ProxyManager", image, "Proxy Manager", menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

    def hide_window(self) -> None:
        self.root.withdraw()

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def quit_app(self) -> None:
        if self.closing:
            return
        ok, message = self.manager.disconnect()
        self._show_message(message)
        if not ok:
            self.show_window()
            return
        self.closing = True
        if self.tray:
            self.tray.stop()
        self.root.destroy()


if __name__ == "__main__":
    ensure_dirs()

    if os.name != "nt":
        raise SystemExit("Эта версия Proxy Manager предназначена для Windows.")

    if not is_admin():
        relaunch_as_admin()

    _instance_mutex = acquire_single_instance_mutex()
    if _instance_mutex is None:
        ctypes.windll.user32.MessageBoxW(
            None,
            "Proxy Manager уже запущен. Откройте его окно из системного трея.",
            "Proxy Manager",
            0x40
        )
        raise SystemExit("Proxy Manager уже запущен. Откройте его окно из системного трея.")

    ProxyApp()
