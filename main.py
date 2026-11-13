from __future__ import annotations

import base64
import ctypes
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
import winreg
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from tkinter import TclError, filedialog, messagebox
from typing import Any, Callable, NamedTuple
from urllib.parse import unquote

import customtkinter as ctk
import pystray
import requests
from PIL import Image, ImageDraw, ImageFont


BASE_DIR = Path(__file__).resolve().parent
BIN_PATH = BASE_DIR / "bin" / "sing-box.exe"
CONFIG_DIR = BASE_DIR / "configs"
CONFIG_PATH = CONFIG_DIR / "proxy.json"
SETTINGS_PATH = BASE_DIR / "settings.json"
ASSETS_DIR = BASE_DIR / "assets"
ICON_PATH = ASSETS_DIR / "icon.ico"
LOG_DIR = BASE_DIR / "logs"
LOG_PATH = LOG_DIR / "sing-box.log"
OLD_LOG_PATH = LOG_DIR / "sing-box.old.log"
APP_LOG_PATH = LOG_DIR / "app.log"
PID_PATH = LOG_DIR / "sing-box.pid"

IP_CHECK_INBOUND_TAG = "ip-check-in"
IP_CHECK_HOST = "api.ipify.org"
MAX_LOG_SIZE = 5 * 1024 * 1024
PROXY_PROBE_TIMEOUT = 8
START_TIMEOUT = 40
STATUS_POLL_MS = 1500
INSTANCE_EVENT_NAME = "Local\\ProxyManagerShowWindow"
POWERSHELL_PATH = Path(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
)
READ_SHORTCUTS_SCRIPT = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    "$shell=New-Object -ComObject WScript.Shell;"
    "$links=$env:PROXY_MANAGER_LINKS|ConvertFrom-Json;"
    "$items=@(foreach($link in $links){$s=$shell.CreateShortcut($link);"
    "[pscustomobject]@{path=$link;target=$s.TargetPath;args=$s.Arguments}});"
    "ConvertTo-Json -InputObject $items -Compress"
)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# Its own process group lets sing-box get Ctrl+Break, on which it removes the TUN adapter.
SINGBOX_FLAGS = NO_WINDOW | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
GRACEFUL_STOP_TIMEOUT = 10
TUN_START_ATTEMPTS = 3
# Run in a separate process: attaching to the console of sing-box would otherwise
# detach this app from its own console.
CTRL_BREAK_SCRIPT = (
    "import ctypes,sys;k=ctypes.WinDLL('kernel32');k.FreeConsole();"
    "pid=int(sys.argv[1]);"
    "ok=k.AttachConsole(pid) and k.SetConsoleCtrlHandler(None,True) "
    "and k.GenerateConsoleCtrlEvent(1,pid);sys.exit(0 if ok else 1)"
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")

PROXY_TYPE_LABELS = {"socks": "SOCKS5", "http": "HTTP"}
PROXY_SCHEMES = {"socks": "socks", "socks5": "socks", "socks5h": "socks", "http": "http"}
ROUTE_MODE_LABELS = {
    "apps": "Выбранные", "except": "Все, кроме выбранных", "all": "Весь компьютер"
}
# The flag of a program in the list that each mode with a list reads.
PROGRAM_FLAGS = {"apps": "enabled", "except": "excluded"}

PAD_X = 24
COLOR_CONNECTED = "#22c77a"
COLOR_DISCONNECTED = "#ef5350"
COLOR_BUSY = "#ffb74d"
COLOR_ICON = "#168bdb"
COLOR_TRAY_OFF = "#7a8394"

# Programs are matched by their full path (see resolve_apps), not by the file name:
# another chrome.exe, e.g. the Chromium of Playwright, does not go through the proxy.
APP_PRESETS: dict[str, str] = {
    "claude": "Claude",
    "chrome": "Google Chrome",
    "vscode": "VS Code",
    "hermes": "Hermes",
}

# The family name of the Claude desktop app package (MSIX); its install folder is
# C:\Program Files\WindowsApps\Claude_<version>_x64__pzs8sxrjxfjjc.
CLAUDE_PACKAGE_PREFIX = "Claude_"
CLAUDE_PACKAGE_SUFFIX = "__pzs8sxrjxfjjc"
APP_PACKAGES_KEY = (
    r"Software\Classes\Local Settings\Software\Microsoft\Windows"
    r"\CurrentVersion\AppModel\Repository\Packages"
)

TUN_ADDRESSES = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
# How often newly started programs of the selected folders are added to the kill switch.
KILL_SWITCH_POLL_S = 5
PROGRAMS_CACHE_PATH = LOG_DIR / "programs-cache.json"
KILL_SWITCH_STATE_PATH = LOG_DIR / "kill-switch-state.json"
# Traffic to these addresses never goes through the proxy (LAN, loopback, multicast),
# so the kill switch leaves it alone.
NON_INTERNET_NETWORKS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/127", "fc00::/7", "fe80::/10", "ff00::/8"
]
# Valve's own networks (AS32590, prefixes announced in RIPE, November 2026): Steam servers
# and most of the Steam Datagram Relay servers that carry Dota 2 and CS2 matches.
VALVE_NETWORKS = [
    "45.121.184.0/24", "103.10.124.0/23", "103.28.54.0/24", "146.66.152.0/24",
    "146.66.155.0/24", "155.133.224.0/21", "155.133.236.0/22", "155.133.240.0/23",
    "155.133.244.0/24", "155.133.246.0/24", "155.133.248.0/22", "155.133.252.0/24",
    "155.133.254.0/23", "162.254.192.0/21", "185.25.180.0/24", "185.25.182.0/23",
    "192.69.96.0/22", "205.196.6.0/24", "208.64.200.0/22", "208.78.164.0/22",
    "2404:3fc0::/46", "2404:3fc0:8::/47", "2404:3fc0:a::/48", "2602:801:f000::/46",
    "2602:801:f005::/48", "2602:801:f006::/47", "2602:801:f008::/46", "2602:801:f00d::/48",
    "2602:801:f00e::/48", "2a01:bc80::/45", "2a01:bc80:8::/46", "2a01:bc80:c::/48"
]
# The other relays are rented from hosting companies (e.g. Datapacket in Frankfurt and
# Vienna); Steam lists the current ones.
STEAM_SDR_CONFIG_URL = "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid={}"
STEAM_GAME_APP_IDS = (570, 730)  # Dota 2, Counter-Strike 2
VALVE_RELAYS_CACHE_PATH = LOG_DIR / "valve-relays.json"

DEFAULT_SETTINGS = {
    "proxy_type": "socks",
    "route_mode": "apps",
    "apps": {key: True for key in APP_PRESETS},
    # The built-in programs that go direct in the "all except the selected" mode.
    "excluded_apps": {key: False for key in APP_PRESETS},
    # Programs added by the user: {"title", "path", "enabled", "excluded"}; the path is
    # an .exe, a folder or a bare name like telegram.exe. "enabled" sends the program
    # through the proxy in the selected programs mode, "excluded" keeps it direct in the
    # "all except the selected" mode.
    "programs": [],
    # Discord and Dota 2 were offered as the first exceptions, see seed_exceptions.
    "exceptions_seeded": False,
    # Without sing-box the selected programs get no internet instead of going direct.
    "kill_switch": True,
    # Dota 2 and CS2 reach Valve's servers past the TUN, see valve_game_networks.
    "games_direct": True,
    # True writes every connection to logs\sing-box.log; otherwise only warnings and errors.
    "verbose_log": False,
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

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
EVENT_MODIFY_STATE = 0x0002
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
SDDL_REVISION_1 = 1
CSIDL_DESKTOPDIRECTORY = 0x10
CSIDL_COMMON_DESKTOPDIRECTORY = 0x19
MAX_PATH = 260


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL)
    ]


# Win32 functions get explicit prototypes, so handles are not truncated on 64-bit Python.
if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateEventW.argtypes = [
        ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR
    ]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenEventW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    kernel32.SetEvent.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.K32EnumProcesses.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.K32EnumProcesses.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    shell32.IsUserAnAdmin.argtypes = []
    shell32.IsUserAnAdmin.restype = wintypes.BOOL
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [wintypes.LPCWSTR]
    shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
    shell32.SHGetFolderPathW.argtypes = [
        wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR
    ]
    shell32.SHGetFolderPathW.restype = ctypes.c_long
    user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
    user32.MessageBoxW.restype = ctypes.c_int


def ensure_dirs() -> None:
    for directory in (CONFIG_DIR, LOG_DIR, ASSETS_DIR):
        directory.mkdir(exist_ok=True)


def log_app_error(text: str) -> None:
    try:
        with APP_LOG_PATH.open("a", encoding="utf-8") as log:
            log.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {text.rstrip()}\n")
    except OSError:
        pass


def install_error_logging() -> None:
    # The elevated instance runs under pythonw.exe, which has no console for tracebacks.
    def excepthook(exc_type, exc, tb) -> None:
        if not issubclass(exc_type, (SystemExit, KeyboardInterrupt)):
            log_app_error("".join(traceback.format_exception(exc_type, exc, tb)))

    sys.excepthook = excepthook
    threading.excepthook = lambda args: excepthook(
        args.exc_type, args.exc_value, args.exc_traceback
    )


def show_message_box(text: str, error: bool = False) -> None:
    user32.MessageBoxW(None, text, "Proxy Manager", 0x10 if error else 0x40)


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def is_ipv6(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
    except ValueError:
        return False


def default_settings() -> dict[str, Any]:
    return json.loads(json.dumps(DEFAULT_SETTINGS))


def update_profile(profile: dict[str, Any], source: dict[str, Any]) -> None:
    for key in profile:
        value = source.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            profile[key] = value


def load_settings() -> dict[str, Any]:
    settings = default_settings()
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return settings
    except (OSError, ValueError) as exc:
        # Keep the broken file: it is overwritten on the next save otherwise.
        try:
            os.replace(SETTINGS_PATH, SETTINGS_PATH.with_name("settings.broken.json"))
        except OSError:
            pass
        log_app_error(f"Не удалось прочитать settings.json: {exc}")
        return settings
    if not isinstance(data, dict):
        return settings

    if data.get("proxy_type") in PROXY_TYPE_LABELS:
        settings["proxy_type"] = data["proxy_type"]
    if data.get("route_mode") in ROUTE_MODE_LABELS:
        settings["route_mode"] = data["route_mode"]

    saved_profiles = data.get("profiles")
    if isinstance(saved_profiles, dict):
        for kind in PROXY_TYPE_LABELS:
            profile = saved_profiles.get(kind)
            if isinstance(profile, dict):
                update_profile(settings["profiles"][kind], profile)
    else:
        # The first version kept a single profile at the top level.
        update_profile(settings["profiles"][settings["proxy_type"]], data)

    saved_apps = data.get("apps")
    if isinstance(saved_apps, dict):
        for key in settings["apps"]:
            if isinstance(saved_apps.get(key), bool):
                settings["apps"][key] = saved_apps[key]
    saved_excluded = data.get("excluded_apps")
    if isinstance(saved_excluded, dict):
        for key in settings["excluded_apps"]:
            if isinstance(saved_excluded.get(key), bool):
                settings["excluded_apps"][key] = saved_excluded[key]

    saved_programs = data.get("programs")
    if isinstance(saved_programs, list):
        for item in saved_programs:
            if isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"].strip():
                add_program(
                    settings["programs"], item["path"].strip(), item.get("title"),
                    item.get("enabled") is not False, item.get("excluded") is True
                )
    elif isinstance(data.get("custom_apps"), str):
        # Earlier versions kept the programs as one line of text.
        for entry in parse_custom_apps(data["custom_apps"]):
            add_program(settings["programs"], entry)
    for key in ("verbose_log", "kill_switch", "games_direct", "exceptions_seeded"):
        if isinstance(data.get(key), bool):
            settings[key] = data[key]
    return settings


def save_settings(data: dict[str, Any]) -> None:
    # For this starter project the credentials are stored locally in settings.json.
    # Restrict access to this file to your Windows account before using it on a shared PC.
    temp_path = SETTINGS_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
    os.replace(temp_path, SETTINGS_PATH)


def parse_custom_apps(text: str) -> list[str]:
    """Entries of the "other programs" field: names like telegram.exe or full paths."""
    entries: dict[str, str] = {}
    # A path with a separator in it comes in quotes (see format_custom_apps).
    for item in re.findall(r'\s*"[^"]*"\s*|[^,;\n]+', text):
        entry = os.path.expandvars(item.strip().strip('"').strip())
        if not entry:
            continue
        if not is_path_entry(entry) and not entry.lower().endswith(".exe"):
            entry += ".exe"
        entries.setdefault(entry.lower(), entry)
    return list(entries.values())


def format_custom_apps(entries: list[str]) -> str:
    return ", ".join(
        f'"{entry}"' if any(char in entry for char in ",;") else entry for entry in entries
    )


def add_program(programs: list[dict[str, Any]], path: str, title: Any = None,
                enabled: bool = True, excluded: bool = False) -> None:
    """Adds a program to the list unless this path is already there."""
    key = os.path.normpath(path).lower()
    if any(os.path.normpath(program["path"]).lower() == key for program in programs):
        return
    if not isinstance(title, str) or not title.strip():
        title = Path(path).stem or path
    programs.append(
        {"title": title.strip(), "path": path, "enabled": enabled, "excluded": excluded}
    )


def programs_text(programs: list[dict[str, Any]], flag: str = "enabled") -> str:
    """The programs of the list with this flag set, in the form resolve_apps takes."""
    return format_custom_apps([program["path"] for program in programs if program[flag]])


def steam_libraries() -> list[Path]:
    """The Steam folder and the other folders it installs games to."""
    roots = []
    for hive, key_path, value in (
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
    ):
        try:
            with winreg.OpenKey(hive, key_path) as key:
                roots.append(Path(os.path.normpath(str(winreg.QueryValueEx(key, value)[0]))))
        except OSError:
            continue
    libraries = list(roots)
    for root in roots:
        try:
            text = (root / "steamapps" / "libraryfolders.vdf").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        libraries += [
            Path(os.path.normpath(path.replace("\\\\", "\\")))
            for path in re.findall(r'"path"\s+"([^"]+)"', text)
        ]
    unique = {str(path).lower(): path for path in libraries}
    return [path for path in unique.values() if path.is_dir()]


def seed_exceptions(settings: dict[str, Any]) -> None:
    """Once, puts Discord and Dota 2 into the exceptions of the "all except" mode."""
    if settings["exceptions_seeded"]:
        return
    settings["exceptions_seeded"] = True
    found: list[tuple[str, Path]] = []
    # Discord runs from a folder per version, so its whole folder is the program.
    discord = env_path("LOCALAPPDATA", "Discord")
    if discord and discord.is_dir():
        found.append(("Discord", discord))
    for library in steam_libraries():
        dota = library / "steamapps" / "common" / "dota 2 beta"
        if dota.is_dir():
            found.append(("Dota 2", dota))
    for title, folder in found:
        key = os.path.normpath(folder).lower()
        for program in settings["programs"]:
            if os.path.normpath(program["path"]).lower() == key:
                program["excluded"] = True
                break
        else:
            add_program(settings["programs"], str(folder), title, enabled=False, excluded=True)


def is_path_entry(entry: str) -> bool:
    return any(char in entry for char in "\\/:")


class AppTargets:
    """What goes through the proxy: exact .exe paths and whole folders."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.dirs: dict[str, str] = {}
        # Folders whose name changes with the version: description -> regexp.
        self.versioned: dict[str, str] = {}

    def add_file(self, path: str | Path) -> None:
        text = os.path.normpath(str(path))
        self.files.setdefault(text.lower(), text)

    def add_dir(self, path: str | Path) -> None:
        text = os.path.normpath(str(path)).rstrip("\\")
        self.dirs.setdefault(text.lower(), text)

    def add_versioned_dir(self, parent: str | Path, prefix: str, suffix: str = "") -> None:
        """A folder parent\\<prefix><anything><suffix>: it keeps matching after an update."""
        parent_text = os.path.normpath(str(parent)).rstrip("\\")
        self.versioned[f"{parent_text}\\{prefix}*{suffix}\\"] = (
            f"(?i)^{go_regex_escape(parent_text)}\\\\{go_regex_escape(prefix)}"
            f"[^\\\\]*{go_regex_escape(suffix)}\\\\"
        )

    def __bool__(self) -> bool:
        return bool(self.files or self.dirs)

    def matches(self, path: str) -> bool:
        normal = os.path.normpath(path)
        lower = normal.lower()
        return (
            lower in self.files
            or any(lower.startswith(d + "\\") for d in self.dirs)
            # The regexps use only syntax that Go and Python share.
            or any(re.match(pattern, normal) for pattern in self.versioned.values())
        )

    def regex_patterns(self) -> list[str]:
        """Case-insensitive Go regexps for sing-box's process_path_regex."""
        return (
            [f"(?i)^{go_regex_escape(path)}$" for path in self.files.values()]
            + [f"(?i)^{go_regex_escape(path)}\\\\" for path in self.dirs.values()]
            + list(self.versioned.values())
        )

    def describe(self) -> list[str]:
        return (
            list(self.files.values()) + [path + "\\" for path in self.dirs.values()]
            + list(self.versioned)
        )


def go_regex_escape(text: str) -> str:
    # re.escape also escapes spaces, which Go regexps reject.
    return re.sub(r"([\\.+*?()|\[\]{}^$])", r"\\\1", text)


def env_path(name: str, *parts: str) -> Path | None:
    base = os.environ.get(name)
    return Path(base, *parts) if base else None


def process_image_path(pid: int) -> str | None:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        image_path = ctypes.create_unicode_buffer(32768)
        path_length = wintypes.DWORD(len(image_path))
        if not kernel32.QueryFullProcessImageNameW(
            handle, 0, image_path, ctypes.byref(path_length)
        ):
            return None
        return image_path.value
    finally:
        kernel32.CloseHandle(handle)


def running_process_paths() -> list[str]:
    pids = (wintypes.DWORD * 8192)()
    needed = wintypes.DWORD()
    if not kernel32.K32EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed)):
        return []
    count = needed.value // ctypes.sizeof(wintypes.DWORD)
    paths = {}
    for pid in pids[:count]:
        path = process_image_path(pid) if pid else None
        if path:
            paths.setdefault(path.lower(), path)
    return list(paths.values())


def registry_app_paths(exe_name: str) -> list[Path]:
    """Paths registered for the program in "App Paths" (what Win+R uses)."""
    found = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(
                hive, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"
            ) as key:
                value, _ = winreg.QueryValueEx(key, "")
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            found.append(Path(os.path.expandvars(value.strip().strip('"'))))
    return found


def registry_install_locations(display_name_prefix: str) -> list[Path]:
    found = []
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                root = winreg.OpenKey(hive, uninstall, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            with root:
                index = 0
                while True:
                    try:
                        name = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(root, name) as key:
                            display_name = str(winreg.QueryValueEx(key, "DisplayName")[0])
                            location = str(winreg.QueryValueEx(key, "InstallLocation")[0])
                    except OSError:
                        continue
                    if display_name.startswith(display_name_prefix) and location.strip():
                        found.append(Path(location.strip().strip('"')))
    return found


def find_chrome(running: list[str]) -> list[Path]:
    # Google Chrome always lives in ...\Google\Chrome\Application\chrome.exe.
    candidates = registry_app_paths("chrome.exe") + [
        path for path in (
            env_path("ProgramFiles", "Google", "Chrome", "Application", "chrome.exe"),
            env_path("ProgramFiles(x86)", "Google", "Chrome", "Application", "chrome.exe"),
            env_path("LOCALAPPDATA", "Google", "Chrome", "Application", "chrome.exe"),
        ) if path
    ] + [
        Path(path) for path in running
        if path.lower().endswith("\\google\\chrome\\application\\chrome.exe")
    ]
    return [path for path in candidates if path.name.lower() == "chrome.exe" and path.is_file()]


def find_vscode(running: list[str]) -> list[Path]:
    """VS Code installation folders."""
    candidates = registry_install_locations("Microsoft Visual Studio Code") + [
        path for path in (
            env_path("LOCALAPPDATA", "Programs", "Microsoft VS Code"),
            env_path("ProgramFiles", "Microsoft VS Code"),
        ) if path
    ] + [Path(path).parent for path in running if Path(path).name.lower() == "code.exe"]
    return [path for path in candidates if (path / "Code.exe").is_file()]


def claude_package_folders() -> list[Path]:
    """Install folders of the Claude desktop app, as Windows registered them for the user."""
    found = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_PACKAGES_KEY) as packages:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(packages, index)
                except OSError:
                    break
                index += 1
                if not (name.startswith(CLAUDE_PACKAGE_PREFIX) and name.endswith(CLAUDE_PACKAGE_SUFFIX)):
                    continue
                try:
                    with winreg.OpenKey(packages, name) as key:
                        found.append(Path(str(winreg.QueryValueEx(key, "PackageRootFolder")[0])))
                except OSError:
                    continue
    except OSError:
        pass
    return [path for path in found if path.is_dir()]


def add_claude(targets: AppTargets) -> bool:
    """The Claude desktop app and Claude Code; False if none of them is installed."""
    found = False
    packages = claude_package_folders()
    for folder in packages:
        targets.add_dir(folder)
    windows_apps = env_path("ProgramFiles", "WindowsApps")
    if packages and windows_apps:
        # The version is in the folder name, so an update moves the app to a new folder.
        targets.add_versioned_dir(windows_apps, CLAUDE_PACKAGE_PREFIX, CLAUDE_PACKAGE_SUFFIX)
        found = True

    folders = [
        # Data of the desktop app; it downloads its own Claude Code there. Newer versions
        # of the app keep the data in Claude-Data instead of the package folder.
        env_path("LOCALAPPDATA", "Packages", CLAUDE_PACKAGE_PREFIX + CLAUDE_PACKAGE_SUFFIX.lstrip("_")),
        env_path("LOCALAPPDATA", "Claude-Data"),
        # The desktop app installed without the Microsoft packaging.
        env_path("LOCALAPPDATA", "AnthropicClaude"),
        # Claude Code installed on its own.
        env_path("USERPROFILE", ".local", "share", "claude"),
    ]
    for folder in folders:
        if folder and folder.is_dir():
            targets.add_dir(folder)
            found = True
    launcher = env_path("USERPROFILE", ".local", "bin", "claude.exe")
    if launcher and launcher.is_file():
        targets.add_file(launcher)
        found = True

    # Claude Code as an extension of VS Code and its forks.
    home = os.environ.get("USERPROFILE")
    for editor in (".vscode", ".vscode-insiders", ".cursor", ".windsurf"):
        extensions = Path(home, editor, "extensions") if home else None
        if not extensions or not extensions.is_dir():
            continue
        installed = [path for path in extensions.glob("anthropic.claude-code-*") if path.is_dir()]
        for folder in installed:
            targets.add_dir(folder)
        if installed:
            targets.add_versioned_dir(extensions, "anthropic.claude-code-")
            found = True
    return found


def resolve_apps(apps: dict[str, bool], custom_apps: str) -> AppTargets:
    """Finds the full paths of the selected programs; ValueError says what is missing."""
    targets = AppTargets()
    running = running_process_paths()

    if apps.get("claude") and not add_claude(targets):
        raise ValueError(
            "Claude не найден: нет ни приложения Claude, ни Claude Code. Снимите галочку "
            "«Claude» или добавьте его .exe кнопкой «+ Добавить программы»."
        )

    if apps.get("chrome"):
        chrome = find_chrome(running)
        if not chrome:
            raise ValueError(
                "Google Chrome не найден в обычных папках установки. Снимите галочку "
                "или добавьте chrome.exe кнопкой «+ Добавить программы»."
            )
        for path in chrome:
            targets.add_file(path)

    if apps.get("vscode"):
        folders = find_vscode(running)
        if not folders:
            raise ValueError(
                "VS Code не найден. Запустите его, снимите галочку или укажите "
                "папку VS Code кнопкой «+ Добавить программы»."
            )
        # The whole folder: Code.exe and the tools bundled with it.
        for folder in folders:
            targets.add_dir(folder)
        # Claude Code, Codex and other extensions run their own executables.
        extensions = env_path("USERPROFILE", ".vscode", "extensions")
        if extensions and extensions.is_dir():
            targets.add_dir(extensions)

    if apps.get("hermes"):
        # Hermes.exe is only the UI: LLM requests come from the backend run by Hermes' own
        # Python, which, like its bundled node/chromium/git, lives in %LOCALAPPDATA%\hermes.
        hermes = env_path("LOCALAPPDATA", "hermes")
        if not hermes or not hermes.is_dir():
            raise ValueError("Папка Hermes (%LOCALAPPDATA%\\hermes) не найдена. Снимите галочку.")
        targets.add_dir(hermes)

    for entry in parse_custom_apps(custom_apps):
        if is_path_entry(entry):
            path = Path(entry)
            if path.is_dir():
                targets.add_dir(path)
            elif path.is_file():
                targets.add_file(path)
            else:
                raise ValueError(
                    f"Не найден файл или папка: {entry}\n"
                    "Снимите галочку у этой программы или удалите её из списка."
                )
            continue
        # A bare name is turned into the paths of the programs with this name.
        found = [path for path in running if Path(path).name.lower() == entry.lower()]
        found += [str(path) for path in registry_app_paths(entry) if path.is_file()]
        if not found:
            raise ValueError(
                f"Не удалось найти путь к {entry}: программа не запущена и не "
                "зарегистрирована в Windows. Запустите её или добавьте её .exe заново."
            )
        for path in found:
            targets.add_file(path)
    return targets


class DesktopApp(NamedTuple):
    title: str
    path: str


class PickerRow(NamedTuple):
    entry: str
    title: str
    checked: bool
    covered: bool


def desktop_folders() -> list[Path]:
    """The desktop of the user and the one shared by all users."""
    folders = []
    for csidl in (CSIDL_DESKTOPDIRECTORY, CSIDL_COMMON_DESKTOPDIRECTORY):
        buffer = ctypes.create_unicode_buffer(MAX_PATH)
        if shell32.SHGetFolderPathW(None, csidl, None, 0, buffer) == 0 and buffer.value:
            folders.append(Path(buffer.value))
    return folders


def read_shortcuts(paths: list[str]) -> dict[str, tuple[str, str]]:
    """Target and arguments of .lnk files, keyed by the lowercase path of the shortcut."""
    if not paths:
        return {}
    # The paths come through the environment, so PowerShell never parses them as code.
    env = {**os.environ, "PROXY_MANAGER_LINKS": json.dumps(paths)}
    try:
        result = subprocess.run(
            [str(POWERSHELL_PATH), "-NoProfile", "-NonInteractive", "-Command", READ_SHORTCUTS_SCRIPT],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8-sig",
            errors="replace",
            timeout=30,
            env=env,
            cwd=str(BASE_DIR),
            creationflags=NO_WINDOW
        )
        items = json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        log_app_error(f"Не удалось прочитать ярлыки: {exc}")
        return {}
    return {
        str(item["path"]).lower(): (str(item.get("target") or ""), str(item.get("args") or ""))
        for item in items if isinstance(item, dict) and item.get("path")
    }


def shortcut_program(target: str, arguments: str) -> str | None:
    """What goes through the proxy for a shortcut: an .exe, a folder or None if not a program."""
    lower = target.lower()
    # Installer stubs and Microsoft Store aliases: the real process runs from another path.
    if not lower.endswith(".exe") or any(
        part in lower for part in ("\\windows\\installer\\", "\\microsoft\\windowsapps\\")
    ):
        return None
    path = Path(target)
    # This app and its interpreter must reach the proxy server directly.
    if path.parent == Path(sys.executable).parent:
        return None
    # Discord, Slack and others run from a folder per version, next to Update.exe;
    # the shortcut leads to Update.exe itself or to a small starter beside it.
    if (path.name.lower() == "update.exe" and "--processstart" in arguments.lower()) or (
        path.with_name("Update.exe").is_file()
    ):
        return str(path.parent)
    # Sites installed as apps start through chrome_proxy.exe, but chrome.exe does the work.
    if lower.endswith("_proxy.exe"):
        real = path.with_name(path.name[:-len("_proxy.exe")] + ".exe")
        if real.is_file():
            return str(real)
    return target


def find_desktop_apps() -> list[DesktopApp]:
    """Programs from the desktop shortcuts and .exe files, without duplicates."""
    links: list[Path] = []
    apps: dict[str, DesktopApp] = {}
    for folder in desktop_folders():
        try:
            items = sorted(folder.iterdir())
        except OSError:
            continue
        for item in items:
            suffix = item.suffix.lower()
            if suffix == ".lnk":
                links.append(item)
            elif suffix == ".exe" and item.is_file():
                apps.setdefault(os.path.normpath(item).lower(), DesktopApp(item.stem, str(item)))

    shortcuts = read_shortcuts([str(link) for link in links])
    for link in links:
        target, arguments = shortcuts.get(str(link).lower(), ("", ""))
        program = shortcut_program(target, arguments)
        if program:
            apps.setdefault(os.path.normpath(program).lower(), DesktopApp(link.stem, program))
    return sorted(apps.values(), key=lambda app: app.title.casefold())


def picker_rows(existing: list[dict[str, Any]], apps: list[DesktopApp],
                covered: AppTargets) -> list[PickerRow]:
    """Rows of the program picker: the programs of the list first, then the rest of the desktop."""
    keys = {os.path.normpath(program["path"]).lower() for program in existing}
    # A bare telegram.exe in the list is the same program as ...\Telegram\Telegram.exe.
    names = {key for key in keys if not is_path_entry(key)}
    rows = [PickerRow(program["path"], program["title"], True, False) for program in existing]
    for app in apps:
        if os.path.normpath(app.path).lower() in keys or Path(app.path).name.lower() in names:
            continue
        is_covered = covered.matches(app.path)
        rows.append(PickerRow(app.path, app.title, is_covered, is_covered))
    return rows


def scan_executables(folder: str) -> list[str]:
    found = []
    for root, _, files in os.walk(folder):
        found += [os.path.join(root, name) for name in files if name.lower().endswith(".exe")]
    return found


# --- Windows Filtering Platform (the engine under Windows Firewall) ---------------------

RPC_C_AUTHN_WINNT = 10
FWP_UINT8 = 1
FWP_BYTE_BLOB_TYPE = 12
FWP_V4_ADDR_MASK = 0x100
FWP_V6_ADDR_MASK = 0x101
FWP_MATCH_EQUAL = 0
FWP_ACTION_BLOCK = 0x1001
FWP_ACTION_PERMIT = 0x1002
FWPM_FILTER_FLAG_PERSISTENT = 0x1
FWPM_SUBLAYER_FLAG_PERSISTENT = 0x1
FWP_E_FILTER_NOT_FOUND = 0x80320003
FWP_E_SUBLAYER_NOT_FOUND = 0x80320007
FWP_E_ALREADY_EXISTS = 0x80320009

LAYER_CONNECT_V4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"
LAYER_CONNECT_V6 = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4"
CONDITION_APP_ID = "d78e1e87-8644-4ea5-9437-d809ecefc971"
CONDITION_LOCAL_ADDRESS = "d9ee00de-c1ef-4617-bfe3-ffd8f5a08957"
CONDITION_REMOTE_ADDRESS = "b235ae9a-1d64-49b8-a44c-5ff3d9095045"
KILL_SWITCH_SUBLAYER = "6f1c0d9e-6d0b-4f57-9a43-2c1a4a6e5b71"
KILL_SWITCH_NAMESPACE = uuid.UUID("0b5c3a52-58a4-4d8e-9a7e-3f9e1f0c2d10")


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)
    ]

    @classmethod
    def of(cls, value: str | uuid.UUID) -> "GUID":
        guid = cls()
        ctypes.memmove(ctypes.byref(guid), uuid.UUID(str(value)).bytes_le, 16)
        return guid


class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]


class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]


class FWP_V6_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_ubyte * 16), ("prefixLength", ctypes.c_ubyte)]


class FWP_VALUE_UNION(ctypes.Union):
    _fields_ = [("uint8", ctypes.c_uint8), ("uint32", ctypes.c_uint32), ("pointer", ctypes.c_void_p)]


class FWP_VALUE0(ctypes.Structure):
    # FWP_CONDITION_VALUE0 has the same layout.
    _fields_ = [("type", ctypes.c_int), ("value", FWP_VALUE_UNION)]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    _fields_ = [("fieldKey", GUID), ("matchType", ctypes.c_int), ("conditionValue", FWP_VALUE0)]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", ctypes.c_wchar_p), ("description", ctypes.c_wchar_p)]


class FWPM_ACTION0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("filterType", GUID)]


class FWPM_FILTER_CONTEXT(ctypes.Union):
    _fields_ = [("rawContext", ctypes.c_uint64), ("providerContextKey", GUID)]


class FWPM_FILTER0(ctypes.Structure):
    _fields_ = [
        ("filterKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.c_void_p),
        ("providerData", FWP_BYTE_BLOB),
        ("layerKey", GUID),
        ("subLayerKey", GUID),
        ("weight", FWP_VALUE0),
        ("numFilterConditions", ctypes.c_uint32),
        ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
        ("action", FWPM_ACTION0),
        ("context", FWPM_FILTER_CONTEXT),
        ("reserved", ctypes.c_void_p),
        ("filterId", ctypes.c_uint64),
        ("effectiveWeight", FWP_VALUE0),
    ]


class FWPM_SUBLAYER0(ctypes.Structure):
    _fields_ = [
        ("subLayerKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.c_void_p),
        ("providerData", FWP_BYTE_BLOB),
        ("weight", ctypes.c_uint16),
    ]


if os.name == "nt":
    fwpuclnt = ctypes.WinDLL("fwpuclnt")
    for _name, _args in {
        "FwpmEngineOpen0": [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.POINTER(wintypes.HANDLE)],
        "FwpmEngineClose0": [wintypes.HANDLE],
        "FwpmTransactionBegin0": [wintypes.HANDLE, ctypes.c_uint32],
        "FwpmTransactionCommit0": [wintypes.HANDLE],
        "FwpmTransactionAbort0": [wintypes.HANDLE],
        "FwpmSubLayerAdd0": [wintypes.HANDLE, ctypes.POINTER(FWPM_SUBLAYER0), ctypes.c_void_p],
        "FwpmSubLayerDeleteByKey0": [wintypes.HANDLE, ctypes.POINTER(GUID)],
        "FwpmFilterAdd0": [wintypes.HANDLE, ctypes.POINTER(FWPM_FILTER0), ctypes.c_void_p,
                           ctypes.POINTER(ctypes.c_uint64)],
        "FwpmFilterDeleteByKey0": [wintypes.HANDLE, ctypes.POINTER(GUID)],
        "FwpmFilterGetByKey0": [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)],
        "FwpmGetAppIdFromFileName0": [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)],
        "FwpmFreeMemory0": [ctypes.POINTER(ctypes.c_void_p)],
    }.items():
        _function = getattr(fwpuclnt, _name)
        _function.argtypes = _args
        _function.restype = None if _name == "FwpmFreeMemory0" else wintypes.DWORD


def wfp_check(code: int, action: str, allowed: tuple[int, ...] = ()) -> int:
    if code and code not in allowed:
        raise RuntimeError(f"WFP: {action} — ошибка 0x{code:08X}")
    return code


def filter_key(name: str) -> GUID:
    return GUID.of(uuid.uuid5(KILL_SWITCH_NAMESPACE, name))


def address_condition(field: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network,
                      keep: list[Any]) -> FWPM_FILTER_CONDITION0:
    condition = FWPM_FILTER_CONDITION0(fieldKey=GUID.of(field), matchType=FWP_MATCH_EQUAL)
    if network.version == 4:
        value = FWP_V4_ADDR_AND_MASK(int(network.network_address), int(network.netmask))
        condition.conditionValue.type = FWP_V4_ADDR_MASK
    else:
        value = FWP_V6_ADDR_AND_MASK(
            (ctypes.c_ubyte * 16)(*network.network_address.packed), network.prefixlen
        )
        condition.conditionValue.type = FWP_V6_ADDR_MASK
    keep.append(value)
    condition.conditionValue.value.pointer = ctypes.addressof(value)
    return condition


class KillSwitch:
    """WFP filters that keep the selected programs off the internet past the TUN.

    In its own sublayer: connections from the TUN address and to LAN addresses are
    permitted, every other outgoing connection of the selected programs is blocked.
    While sing-box runs, their traffic goes through the TUN and is not affected; once
    sing-box stops, it is blocked instead of going direct. The filters are persistent:
    they stay until disarm(), even across reboots. All of them change in one
    transaction, so there is no moment without protection while the list is updated.
    """

    FILTERS = [
        (layer, kind)
        for layer in ("v4", "v6")
        for kind in ("permit-tun", "permit-lan", "block-apps")
    ]

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.covered: set[str] = set()
        self.programs: dict[str, str] = {}
        self.is_armed = False

    @property
    def armed(self) -> bool:
        return self.is_armed

    @staticmethod
    def _open() -> wintypes.HANDLE:
        engine = wintypes.HANDLE()
        wfp_check(
            fwpuclnt.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(engine)),
            "подключение к Base Filtering Engine"
        )
        return engine

    def _transaction(self, work: Callable[[wintypes.HANDLE], None]) -> None:
        engine = self._open()
        try:
            wfp_check(fwpuclnt.FwpmTransactionBegin0(engine, 0), "начало транзакции")
            try:
                work(engine)
            except BaseException:
                fwpuclnt.FwpmTransactionAbort0(engine)
                raise
            wfp_check(fwpuclnt.FwpmTransactionCommit0(engine), "сохранение транзакции")
        finally:
            fwpuclnt.FwpmEngineClose0(engine)

    def _delete_filters(self, engine: wintypes.HANDLE) -> None:
        for layer, kind in self.FILTERS:
            key = filter_key(f"{layer}-{kind}")
            wfp_check(
                fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(key)),
                "удаление фильтра", (FWP_E_FILTER_NOT_FOUND,)
            )

    def _add_filters(self, engine: wintypes.HANDLE, programs: list[str]) -> int:
        """Adds the filters; returns how many programs got into the block list."""
        sublayer = FWPM_SUBLAYER0(
            subLayerKey=GUID.of(KILL_SWITCH_SUBLAYER),
            displayData=FWPM_DISPLAY_DATA0("Proxy Manager kill switch", None),
            flags=FWPM_SUBLAYER_FLAG_PERSISTENT,
            weight=0x100
        )
        wfp_check(
            fwpuclnt.FwpmSubLayerAdd0(engine, ctypes.byref(sublayer), None),
            "создание подуровня", (FWP_E_ALREADY_EXISTS,)
        )

        app_ids: list[ctypes.c_void_p] = []
        keep: list[Any] = []
        try:
            for path in programs:
                blob = ctypes.c_void_p()
                # Fails for files that no longer exist; those need no blocking.
                if fwpuclnt.FwpmGetAppIdFromFileName0(path, ctypes.byref(blob)) == 0:
                    app_ids.append(blob)
            if not app_ids:
                raise RuntimeError("Не найдено ни одной программы для блокировки.")

            for layer, kind in self.FILTERS:
                version = 4 if layer == "v4" else 6
                conditions: list[FWPM_FILTER_CONDITION0] = []
                if kind == "permit-tun":
                    networks = [n for n in map(lambda t: ipaddress.ip_network(t, strict=False), TUN_ADDRESSES)
                                if n.version == version]
                    conditions = [address_condition(CONDITION_LOCAL_ADDRESS, n, keep) for n in networks]
                elif kind == "permit-lan":
                    networks = [n for n in map(ipaddress.ip_network, NON_INTERNET_NETWORKS)
                                if n.version == version]
                    conditions = [address_condition(CONDITION_REMOTE_ADDRESS, n, keep) for n in networks]
                else:
                    # Conditions on the same field are OR-ed: any of the programs.
                    for blob in app_ids:
                        condition = FWPM_FILTER_CONDITION0(
                            fieldKey=GUID.of(CONDITION_APP_ID), matchType=FWP_MATCH_EQUAL
                        )
                        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE
                        condition.conditionValue.value.pointer = blob.value
                        conditions.append(condition)
                array = (FWPM_FILTER_CONDITION0 * len(conditions))(*conditions)
                filter_ = FWPM_FILTER0(
                    filterKey=filter_key(f"{layer}-{kind}"),
                    displayData=FWPM_DISPLAY_DATA0(f"Proxy Manager kill switch: {kind} {layer}", None),
                    flags=FWPM_FILTER_FLAG_PERSISTENT,
                    layerKey=GUID.of(LAYER_CONNECT_V4 if version == 4 else LAYER_CONNECT_V6),
                    subLayerKey=GUID.of(KILL_SWITCH_SUBLAYER),
                    numFilterConditions=len(conditions),
                    filterCondition=array,
                )
                # Within the sublayer the heaviest matching filter decides: permits win.
                filter_.weight.type = FWP_UINT8
                filter_.weight.value.uint8 = 1 if kind == "block-apps" else 15
                filter_.action.type = FWP_ACTION_BLOCK if kind == "block-apps" else FWP_ACTION_PERMIT
                wfp_check(
                    fwpuclnt.FwpmFilterAdd0(engine, ctypes.byref(filter_), None, None),
                    f"добавление фильтра {kind} {layer}"
                )
            return len(app_ids)
        finally:
            for blob in app_ids:
                fwpuclnt.FwpmFreeMemory0(ctypes.byref(blob))

    def _save_state(self) -> None:
        try:
            KILL_SWITCH_STATE_PATH.write_text(
                json.dumps({"armed": self.is_armed, "programs": sorted(self.programs.values())},
                           ensure_ascii=False),
                encoding="utf-8"
            )
        except OSError:
            pass

    def refresh(self) -> None:
        """Reads from WFP whether the filters are in place."""
        with self.lock:
            engine = self._open()
            try:
                key = filter_key("v4-block-apps")
                result = ctypes.c_void_p()
                code = fwpuclnt.FwpmFilterGetByKey0(engine, ctypes.byref(key), ctypes.byref(result))
                wfp_check(code, "чтение фильтра", (FWP_E_FILTER_NOT_FOUND,))
                if result:
                    fwpuclnt.FwpmFreeMemory0(ctypes.byref(result))
                self.is_armed = code == 0
            finally:
                fwpuclnt.FwpmEngineClose0(engine)
            self.programs = {}
            if self.is_armed:
                try:
                    state = json.loads(KILL_SWITCH_STATE_PATH.read_text(encoding="utf-8"))
                    self.programs = {path.lower(): path for path in state.get("programs", [])}
                except (OSError, ValueError, AttributeError, TypeError):
                    pass
            self.covered = set(self.programs)

    def arm(self, programs: list[str]) -> None:
        """Replaces the filters with a set for these programs in one transaction."""
        with self.lock:
            wanted = {path.lower(): path for path in programs}
            self._transaction(lambda engine: (
                self._delete_filters(engine), self._add_filters(engine, list(wanted.values()))
            ))
            self.is_armed = True
            self.programs = wanted
            self.covered = set(wanted)
            self._save_state()

    def extend(self, programs: list[str]) -> int:
        """Adds programs not covered yet; returns how many were added."""
        with self.lock:
            missing = {path.lower(): path for path in programs if path.lower() not in self.covered}
            if not self.is_armed or not missing:
                return 0
            wanted = {**self.programs, **missing}
            self._transaction(lambda engine: (
                self._delete_filters(engine), self._add_filters(engine, list(wanted.values()))
            ))
            self.programs = wanted
            self.covered = set(wanted)
            self._save_state()
            return len(missing)

    def disarm(self) -> None:
        with self.lock:
            def work(engine: wintypes.HANDLE) -> None:
                self._delete_filters(engine)
                key = GUID.of(KILL_SWITCH_SUBLAYER)
                wfp_check(
                    fwpuclnt.FwpmSubLayerDeleteByKey0(engine, ctypes.byref(key)),
                    "удаление подуровня", (FWP_E_SUBLAYER_NOT_FOUND,)
                )
            self._transaction(work)
            self.is_armed = False
            self.programs = {}
            self.covered = set()
            self._save_state()


def load_programs_cache() -> dict[str, list[str]]:
    try:
        data = json.loads(PROGRAMS_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_programs_cache(cache: dict[str, list[str]]) -> None:
    try:
        PROGRAMS_CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def parse_proxy_string(text: str) -> dict[str, str] | None:
    """Splits a proxy line pasted into the host field into form fields.

    Accepts "socks5://login:password@host:port", "login:password@host:port",
    "host:port:login:password" and "host:port". Returns None for a plain host.
    """
    text = text.strip().rstrip("/")
    fields: dict[str, str] = {}
    scheme, separator, rest = text.partition("://")
    if separator:
        proxy_type = PROXY_SCHEMES.get(scheme.lower())
        if proxy_type is None:
            return None
        fields["proxy_type"] = proxy_type
        text = rest

    credentials, at, address = text.rpartition("@")
    if at:
        username, _, password = credentials.partition(":")
        if separator:
            username, password = unquote(username), unquote(password)
        fields["username"] = username
        fields["password"] = password
        text = address

    if text.startswith("["):
        host, _, tail = text[1:].partition("]")
        extra = tail.lstrip(":").split(":") if tail else []
    elif is_ipv6(text):
        host, extra = text, []
    else:
        host, *extra = text.split(":")

    if extra:
        fields["port"] = extra[0]
        if len(extra) >= 3 and not at:
            fields["username"] = extra[1]
            fields["password"] = ":".join(extra[2:])
        elif len(extra) > 1:
            return None
    if not host or not fields:
        return None
    fields["host"] = host
    return fields


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("сервер закрыл соединение")
        data += chunk
    return data


def probe_http_proxy(sock: socket.socket, data: dict[str, Any]) -> str | None:
    request = f"CONNECT {IP_CHECK_HOST}:443 HTTP/1.1\r\nHost: {IP_CHECK_HOST}:443\r\n"
    if data["username"] or data["password"]:
        token = base64.b64encode(f"{data['username']}:{data['password']}".encode("utf-8"))
        request += f"Proxy-Authorization: Basic {token.decode('ascii')}\r\n"
    sock.sendall((request + "\r\n").encode("ascii"))

    response = b""
    while b"\r\n" not in response and len(response) < 4096:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("latin-1").strip()
    parts = status_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return "Сервер не отвечает как HTTP-прокси. Проверьте порт и тип прокси."
    if parts[1] == "407":
        return "HTTP-прокси отклонил логин или пароль."
    if not parts[1].startswith("2"):
        return f"HTTP-прокси вернул ошибку: {status_line}"
    return None


def probe_socks_proxy(sock: socket.socket, data: dict[str, Any]) -> str | None:
    username = data["username"].encode("utf-8")
    password = data["password"].encode("utf-8")
    if len(username) > 255 or len(password) > 255:
        return "Логин и пароль SOCKS5 не могут быть длиннее 255 байт."
    has_auth = bool(username or password)
    # Like sing-box, offer only "login and password" when they are set (RFC 1928, 1929).
    sock.sendall(b"\x05\x01\x02" if has_auth else b"\x05\x01\x00")
    version, method = recv_exact(sock, 2)
    if version != 5:
        return "Сервер не отвечает как SOCKS5-прокси. Проверьте порт и тип прокси."
    if method == 0xFF:
        if has_auth:
            return "SOCKS5-прокси не принимает авторизацию по логину и паролю."
        return "SOCKS5-прокси требует логин и пароль."
    if method == 0x02:
        sock.sendall(
            b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
        )
        if recv_exact(sock, 2)[1] != 0:
            return "SOCKS5-прокси отклонил логин или пароль."
    elif method != 0x00:
        return f"SOCKS5-прокси предложил неподдерживаемый способ авторизации ({method})."
    return None


def probe_proxy(data: dict[str, Any]) -> str | None:
    """Checks that the proxy accepts connections and credentials; returns the problem or None."""
    host, port = data["host"], data["port"]
    address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=PROXY_PROBE_TIMEOUT) as sock:
            if data["proxy_type"] == "http":
                return probe_http_proxy(sock, data)
            return probe_socks_proxy(sock, data)
    except socket.gaierror:
        return f"Не удалось найти адрес прокси-сервера {host}. Проверьте написание."
    except TimeoutError:
        return f"Прокси-сервер {address} не ответил за {PROXY_PROBE_TIMEOUT} секунд."
    except ConnectionRefusedError:
        return f"Прокси-сервер {address} отклонил подключение. Проверьте адрес и порт."
    except OSError as exc:
        return f"Не удалось подключиться к прокси-серверу {address}: {exc}"


def fetch_external_ip(proxy: str | None) -> str:
    with requests.Session() as session:
        # HTTP(S)_PROXY variables must not affect the direct check.
        session.trust_env = False
        try:
            response = session.get(
                f"https://{IP_CHECK_HOST}", timeout=10,
                proxies={"http": proxy, "https": proxy} if proxy else None
            )
            response.raise_for_status()
            return str(ipaddress.ip_address(response.text.strip()))
        except (requests.RequestException, ValueError):
            return "не удалось получить"


def valve_game_networks() -> list[str]:
    """Networks of Valve's game servers, to route around the TUN.

    Even when they go direct, games suffer inside the TUN: every UDP packet passes the
    userspace network stack of sing-box, and the hundreds of relays Steam pings at once to
    pick a region each cost a process lookup, which distorts the pings.
    """
    relays: set[str] = set()
    try:
        with requests.Session() as session:
            session.trust_env = False
            for app_id in STEAM_GAME_APP_IDS:
                response = session.get(STEAM_SDR_CONFIG_URL.format(app_id), timeout=5)
                response.raise_for_status()
                for pop in response.json().get("pops", {}).values():
                    relays.update(relay["ipv4"] for relay in pop.get("relays", []) if relay.get("ipv4"))
        VALVE_RELAYS_CACHE_PATH.write_text(json.dumps(sorted(relays)), encoding="utf-8")
    except (requests.RequestException, ValueError, AttributeError, KeyError, TypeError, OSError):
        try:
            relays = set(json.loads(VALVE_RELAYS_CACHE_PATH.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            relays = set()

    valve = [ipaddress.ip_network(network) for network in VALVE_NETWORKS]
    extra = set()
    for relay in relays:
        try:
            address = ipaddress.ip_address(relay)
        except ValueError:
            continue
        if not any(address in network for network in valve):
            # Relays come in pairs from one /24; a route per /24 keeps the table short.
            extra.add(ipaddress.ip_network(f"{address}/24", strict=False))
    return VALVE_NETWORKS + [str(network) for network in sorted(extra)]


def rotate_log() -> None:
    try:
        if LOG_PATH.stat().st_size > MAX_LOG_SIZE:
            os.replace(LOG_PATH, OLD_LOG_PATH)
    except OSError:
        pass


def make_icon_image(color: str, size: int = 64) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((1, 1, size - 2, size - 2), fill=color)
    font_size = int(size * 0.62)
    try:
        font = ImageFont.truetype("segoeuib.ttf", font_size)
    except OSError:
        font = ImageFont.load_default(font_size)
    left, top, right, bottom = draw.textbbox((0, 0), "P", font=font)
    draw.text(
        ((size - right - left) / 2, (size - bottom - top) / 2),
        "P", fill="white", font=font
    )
    return image


def ensure_icon_file() -> bool:
    if ICON_PATH.is_file():
        return True
    try:
        make_icon_image(COLOR_ICON, 256).save(
            ICON_PATH, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)]
        )
    except OSError:
        return False
    return True


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin() -> None:
    # pythonw.exe runs the elevated GUI without an extra console window.
    executable = Path(sys.executable)
    windowless = executable.with_name("pythonw.exe")
    if windowless.is_file():
        executable = windowless
    params = subprocess.list2cmdline([str(Path(__file__).resolve()), *sys.argv[1:]])
    result = shell32.ShellExecuteW(None, "runas", str(executable), params, str(BASE_DIR), 1)
    if (result or 0) <= 32:
        show_message_box(
            "Proxy Manager нужны права администратора, чтобы создать TUN-интерфейс. "
            "Запуск отменён.",
            error=True
        )


def signal_running_instance() -> bool:
    """Asks an already running instance to show its window; False if there is none."""
    event = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, INSTANCE_EVENT_NAME)
    if event:
        kernel32.SetEvent(event)
        kernel32.CloseHandle(event)
        return True
    if ctypes.get_last_error() == ERROR_ACCESS_DENIED:
        show_message_box("Proxy Manager уже запущен. Откройте его окно из системного трея.")
        return True
    return False


def create_instance_event() -> int | None:
    """Creates the event that marks the running instance and returns its handle.

    Returns None if another instance already runs: it is asked to show its window instead.
    """
    # Everyone at medium integrity may signal the event, so a non-elevated launch
    # can reach the elevated instance before asking for UAC.
    descriptor = ctypes.c_void_p()
    candidates: list[SECURITY_ATTRIBUTES | None] = [None]
    if advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:(A;;GA;;;WD)S:(ML;;NW;;;ME)", SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        # Default security is the fallback if the system refuses this descriptor.
        candidates.insert(
            0, SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        )
    event, error = None, 0
    try:
        for security in candidates:
            ctypes.set_last_error(0)
            event = kernel32.CreateEventW(
                ctypes.byref(security) if security is not None else None,
                False, False, INSTANCE_EVENT_NAME
            )
            error = ctypes.get_last_error()
            if event:
                break
    finally:
        if descriptor:
            kernel32.LocalFree(descriptor)
    if not event:
        raise ctypes.WinError(error)
    if error == ERROR_ALREADY_EXISTS:
        kernel32.SetEvent(event)
        kernel32.CloseHandle(event)
        return None
    return event


def send_ctrl_break(pid: int) -> bool:
    """Asks sing-box to shut down cleanly, as Ctrl+Break in its console would."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", CTRL_BREAK_SCRIPT, str(pid)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
            creationflags=NO_WINDOW
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


class ProxyManager:
    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.log_offset = 0
        self.lock = threading.Lock()
        self.kill_switch = KillSwitch()
        # The programs of the current connection, for the kill switch to follow.
        self.targets: AppTargets | None = None
        self.programs_cache = load_programs_cache()
        self.cache_lock = threading.Lock()

    def is_running(self) -> bool:
        process = self.process
        if process is not None:
            return process.poll() is None
        pid = self._tracked_pid()
        return pid is not None and self._is_singbox_process(pid)

    def reap_exited(self) -> str | None:
        """Cleans up after sing-box stopped without disconnect(); returns the reason if known."""
        if not self.lock.acquire(blocking=False):
            return None
        try:
            if self.process is None:
                pid = self._tracked_pid()
                if pid is not None and not self._is_singbox_process(pid):
                    self._remove_pid_file(pid)
                return None
            if self.process.poll() is None:
                return None
            code = self.process.returncode
            self._remove_pid_file(self.process.pid)
            self.process = None
            return f"sing-box неожиданно завершился (код {code}).\n{self._log_tail()}".strip()
        finally:
            self.lock.release()

    def _tracked_pid(self) -> int | None:
        try:
            pid = int(PID_PATH.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None
        return pid if pid > 0 else None

    @staticmethod
    def _is_singbox_process(pid: int) -> bool:
        image_path = process_image_path(pid)
        return image_path is not None and Path(image_path).resolve() == BIN_PATH.resolve()

    def _remove_pid_file(self, pid: int | None = None) -> None:
        if pid is not None and self._tracked_pid() != pid:
            return
        PID_PATH.unlink(missing_ok=True)

    def _log_tail(self, limit: int = 1500) -> str:
        """The end of what the current sing-box run wrote to the log."""
        try:
            with LOG_PATH.open("rb") as log:
                size = log.seek(0, os.SEEK_END)
                log.seek(max(self.log_offset, size - limit * 4))
                text = log.read().decode("utf-8", errors="replace")
        except OSError:
            return ""
        return strip_ansi(text).strip()[-limit:]

    def build_config(self, data: dict[str, Any], ip_check_port: int) -> dict[str, Any]:
        proxy_type = data.get("proxy_type", "socks")
        if proxy_type not in PROXY_TYPE_LABELS:
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

        route_all = data.get("route_mode") in ("all", "except")
        # Which traffic the rules for the proxied programs apply to; no condition means all.
        proxied = {} if route_all else {"process_path_regex": data["app_patterns"]}
        rules: list[dict[str, Any]] = [
            {
                "inbound": [IP_CHECK_INBOUND_TAG],
                "action": "route",
                "outbound": "proxy"
            }
        ]
        if route_all:
            rules += [
                # DNS first: its server is on the TUN, and that is a private address.
                {
                    "port": 53,
                    "action": "hijack-dns"
                },
                # The router, printers and other LAN devices stay reachable.
                {
                    "ip_is_private": True,
                    "action": "route",
                    "outbound": "direct"
                }
            ]
            if data.get("route_mode") == "except" and data.get("excluded_patterns"):
                # Before the rules of an HTTP proxy: the exceptions keep their UDP and IPv6.
                rules.append({
                    "process_path_regex": data["excluded_patterns"],
                    "action": "route",
                    "outbound": "direct"
                })
        if proxy_type == "http":
            rules += [
                {
                    **proxied,
                    "ip_version": 6,
                    "action": "reject"
                },
                {
                    **proxied,
                    "network": "udp",
                    "action": "reject"
                }
            ]
        if not route_all:
            rules.append({
                **proxied,
                "action": "route",
                "outbound": "proxy"
            })

        dns_servers: list[dict[str, Any]] = [{"type": "local", "tag": "dns-local"}]
        if route_all:
            # DNS over HTTPS works through both proxy types, unlike DNS over UDP.
            dns_servers.append({
                "type": "https",
                "tag": "dns-remote",
                "server": "1.1.1.1",
                "server_port": 443,
                "path": "/dns-query",
                "detour": "proxy"
            })

        tun: dict[str, Any] = {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "singbox",
            "address": TUN_ADDRESSES,
            "auto_route": True,
            "strict_route": True
        }
        if data.get("games_networks"):
            # No routes into the TUN for these: Windows sends them out directly.
            tun["route_exclude_address"] = data["games_networks"]

        return {
            "log": {
                # "info" logs every connection: about 10 MB per hour of browsing.
                "level": "info" if data.get("verbose_log") else "warn",
                "timestamp": True
            },
            "dns": {
                # For selected programs: DNS servers of the physical adapter, the same as
                # without the proxy. For the whole computer: through the proxy, without leaks;
                # dns-local then only resolves the address of the proxy server itself.
                "servers": dns_servers,
                "final": "dns-remote" if route_all else "dns-local",
                # The TUN has an IPv6 address, so without this apps would try IPv6
                # even when the network has no IPv6 connectivity.
                "strategy": "ipv4_only"
            },
            "inbounds": [
                tun,
                {
                    # Lets the app check the external IP of the proxied apps.
                    "type": "http",
                    "tag": IP_CHECK_INBOUND_TAG,
                    "listen": "127.0.0.1",
                    "listen_port": ip_check_port
                }
            ],
            "outbounds": [
                outbound,
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "route": {
                "auto_detect_interface": True,
                "default_domain_resolver": "dns-local",
                "rules": rules,
                "final": "proxy" if route_all else "direct"
            }
        }

    def write_config(self, data: dict[str, Any], path: Path = CONFIG_PATH) -> int:
        ip_check_port = find_free_port()
        path.write_text(
            json.dumps(self.build_config(data, ip_check_port), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        return ip_check_port

    def build_iphone_config(self, data: dict[str, Any]) -> dict[str, Any]:
        """A profile for the sing-box MT app on iPhone: the whole phone through the proxy."""
        config = self.build_config({**data, "route_mode": "all", "verbose_log": False}, 0)
        # iOS manages the TUN itself: it names the interface and has no strict_route.
        config["inbounds"] = [{
            "type": "tun",
            "tag": "tun-in",
            "address": TUN_ADDRESSES,
            "auto_route": True
        }]
        # The IP check inbound is only for this app on the computer.
        config["route"]["rules"] = [rule for rule in config["route"]["rules"] if "inbound" not in rule]
        return config

    def _active_config(self) -> dict[str, Any]:
        if not self.is_running():
            return {}
        try:
            config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return config if isinstance(config, dict) else {}

    def ip_check_proxy(self) -> str | None:
        for inbound in self._active_config().get("inbounds", []):
            if inbound.get("tag") == IP_CHECK_INBOUND_TAG and inbound.get("listen_port"):
                return f"http://127.0.0.1:{inbound['listen_port']}"
        return None

    def active_endpoint(self) -> str | None:
        for outbound in self._active_config().get("outbounds", []):
            if outbound.get("tag") == "proxy":
                server = str(outbound.get("server", ""))
                if ":" in server:
                    server = f"[{server}]"
                kind = PROXY_TYPE_LABELS.get(outbound.get("type"), "?")
                mode = {"all": " · весь компьютер", "except": " · все, кроме выбранных"}.get(
                    self.active_mode(), ""
                )
                return f"{kind} · {server}:{outbound.get('server_port')}{mode}"
        return None

    def active_mode(self) -> str | None:
        """The route mode of the running sing-box."""
        route = self._active_config().get("route")
        if not route:
            return None
        if route.get("final") != "proxy":
            return "apps"
        has_exceptions = any(
            "process_path_regex" in rule and rule.get("outbound") == "direct"
            for rule in route.get("rules", [])
        )
        return "except" if has_exceptions else "all"

    def routes_everything(self) -> bool:
        """The running sing-box sends the whole computer through the proxy."""
        return self._active_config().get("route", {}).get("final") == "proxy"

    def _wait_until_started(self, ip_check_port: int) -> bool:
        # The IP check inbound comes after the TUN, so once it listens the TUN is up.
        # Creating the TUN adapter can take a while, e.g. right after Windows starts.
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", ip_check_port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            return False
        time.sleep(0.3)
        return self.process.poll() is None

    def kill_switch_programs(self, targets: AppTargets, scan: bool = False) -> list[str]:
        """The .exe files the kill switch covers.

        Folders hold hundreds of thousands of files, so their .exe lists come from a cache
        that scan=True refreshes; running programs from the folders are always added.
        """
        programs = dict(targets.files)
        for key, folder in targets.dirs.items():
            if scan:
                found = scan_executables(folder)
                with self.cache_lock:
                    self.programs_cache[key] = found
                    save_programs_cache(dict(self.programs_cache))
            else:
                with self.cache_lock:
                    found = list(self.programs_cache.get(key, []))
            for path in found:
                programs.setdefault(path.lower(), path)
        for path in running_process_paths():
            if targets.matches(path):
                programs.setdefault(path.lower(), path)
        # sing-box and this app must reach the proxy server directly.
        for path in (str(BIN_PATH), process_image_path(os.getpid())):
            if path:
                programs.pop(os.path.normpath(path).lower(), None)
        return list(programs.values())

    def follow_programs(self, scan: bool = False) -> int:
        """Adds kill switch rules for new programs of the selected folders."""
        targets = self.targets
        if targets is None or not self.kill_switch.armed:
            return 0
        return self.kill_switch.extend(self.kill_switch_programs(targets, scan=scan))

    def _undo_kill_switch(self, was_armed: bool) -> None:
        # A failed first connection should not leave the programs without internet.
        if was_armed or not self.kill_switch.armed:
            return
        try:
            self.kill_switch.disarm()
        except Exception:
            log_app_error(traceback.format_exc())

    def _start_singbox(self, ip_check_port: int) -> bool:
        # sing-box keeps its own copy of the handle, so ours can be closed at once.
        with LOG_PATH.open("ab") as log:
            self.log_offset = log.seek(0, os.SEEK_END)
            self.process = subprocess.Popen(
                [str(BIN_PATH), "run", "--disable-color", "-c", str(CONFIG_PATH)],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=str(BASE_DIR),
                creationflags=SINGBOX_FLAGS
            )
        PID_PATH.write_text(str(self.process.pid), encoding="ascii")
        return self._wait_until_started(ip_check_port)

    def connect(self, data: dict[str, Any]) -> tuple[bool, str]:
        """Starts sing-box; a running one is replaced (reconnect) without a gap in the kill switch."""
        with self.lock:
            if not BIN_PATH.is_file():
                return False, (
                    "Не найден bin\\sing-box.exe. Скачайте Windows amd64 "
                    "версию sing-box и положите sing-box.exe в папку bin."
                )

            # With the whole computer proxied, this app's own traffic goes through sing-box
            # too, and the check below would reach the proxy server through itself.
            if self.routes_everything():
                try:
                    self._stop_singbox()
                except Exception as exc:
                    return False, f"Не удалось остановить sing-box: {exc}"

            problem = probe_proxy(data)
            if problem:
                return False, problem
            if data.get("games_direct"):
                data = {**data, "games_networks": valve_game_networks()}

            was_armed = self.kill_switch.armed
            new_config = CONFIG_PATH.with_name("proxy.new.json")
            try:
                ip_check_port = self.write_config(data, new_config)
                check = subprocess.run(
                    [str(BIN_PATH), "check", "--disable-color", "-c", str(new_config)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=20,
                    cwd=str(BASE_DIR),
                    creationflags=NO_WINDOW
                )
                if check.returncode != 0:
                    detail = strip_ansi(check.stderr or check.stdout or "Неизвестная ошибка").strip()
                    return False, f"Ошибка конфигурации sing-box:\n{detail}"

                if self.is_running():
                    self._stop_singbox()
                os.replace(new_config, CONFIG_PATH)

                targets: AppTargets = data["targets"]
                if data["kill_switch"]:
                    self.kill_switch.arm(self.kill_switch_programs(targets))
                elif self.kill_switch.armed:
                    self.kill_switch.disarm()
                self.targets = targets

                rotate_log()
                for attempt in range(1, TUN_START_ATTEMPTS + 1):
                    if self._start_singbox(ip_check_port):
                        break
                    tail = self._log_tail()
                    self._stop_own_process()
                    # Windows sometimes refuses to create the TUN adapter for a while,
                    # e.g. while removing the adapter of a previous run.
                    if "tun interface" not in tail or attempt == TUN_START_ATTEMPTS:
                        break
                    time.sleep(3 * attempt)
                if self.process is None:
                    self._undo_kill_switch(was_armed)
                    hint = ""
                    if "tun interface" in tail:
                        hint = (
                            "\nWindows не дала создать TUN-адаптер. Часто так бывает сразу после "
                            "загрузки или пока другой VPN (PlanetVPN, WireGuard и т. п.) поднимает "
                            "свой туннель на том же драйвере Wintun. Подождите минуту и нажмите "
                            "«Подключить» ещё раз."
                        )
                    return False, "sing-box не запустился.\n" + tail + hint

                return True, "Прокси подключён. Проверяем внешний IP..."
            except subprocess.TimeoutExpired:
                return False, "Проверка конфигурации заняла слишком много времени."
            except Exception as exc:
                log_app_error(traceback.format_exc())
                self._stop_own_process()
                self._undo_kill_switch(was_armed)
                return False, f"Не удалось запустить sing-box: {exc}"
            finally:
                new_config.unlink(missing_ok=True)

    def _stop_own_process(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            if send_ctrl_break(self.process.pid):
                try:
                    self.process.wait(timeout=GRACEFUL_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    pass
        if self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._remove_pid_file(self.process.pid)
        self.process = None

    def _stop_singbox(self) -> str:
        """Stops sing-box and returns what happened; raises if it could not."""
        if self.process is not None:
            pid = self.process.pid
            if self.process.poll() is None:
                # A killed sing-box leaves its TUN adapter behind, and the next start
                # then fails to create one; Ctrl+Break lets it remove the adapter.
                stopped = False
                if send_ctrl_break(pid):
                    try:
                        self.process.wait(timeout=GRACEFUL_STOP_TIMEOUT)
                        stopped = True
                    except subprocess.TimeoutExpired:
                        pass
                if not stopped:
                    self._force_stop(pid)
                    self.process.wait(timeout=5)
            self._remove_pid_file(pid)
            self.process = None
            return "Прокси отключён."

        pid = self._tracked_pid()
        if pid is None:
            return "Прокси уже отключён."
        if not self._is_singbox_process(pid):
            self._remove_pid_file(pid)
            return "Запущенный sing-box не найден; файл состояния очищен."
        if send_ctrl_break(pid):
            deadline = time.monotonic() + GRACEFUL_STOP_TIMEOUT
            while time.monotonic() < deadline and self._is_singbox_process(pid):
                time.sleep(0.2)
        if self._is_singbox_process(pid):
            self._force_stop(pid)
        self._remove_pid_file(pid)
        return "Зависший sing-box остановлен."

    def disconnect(self) -> tuple[bool, str]:
        """Stops sing-box and removes the kill switch: the programs go direct again."""
        with self.lock:
            try:
                message = self._stop_singbox()
            except Exception as exc:
                return False, f"Не удалось остановить sing-box: {exc}"
            self.targets = None
            if self.kill_switch.armed:
                try:
                    self.kill_switch.disarm()
                except Exception as exc:
                    log_app_error(traceback.format_exc())
                    return False, f"{message}\nНе удалось снять kill switch: {exc}"
                message += " Kill switch снят, программы снова ходят в сеть напрямую."
            return True, message

    @staticmethod
    def _force_stop(pid: int) -> None:
        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            # Console tools print in the OEM code page (cp866 on Russian Windows).
            encoding="oem",
            errors="replace",
            timeout=10,
            creationflags=NO_WINDOW
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(detail or f"taskkill завершился с кодом {result.returncode}")


class ProxyApp:
    def __init__(self, instance_event: int | None = None) -> None:
        self.manager = ProxyManager()
        self.settings = load_settings()
        self.closing = False
        self.quitting = False
        self.operations = 0
        self.busy_text = ""
        self.running = False
        self.ip_check_id = 0
        self.following = False
        self.next_follow = 0.0
        self.tray: pystray.Icon | None = None
        self.tray_hint_shown = False
        self.picker: AppPicker | None = None
        self.program_rows: list[Any] = []
        self.ui_calls: queue.SimpleQueue[Callable[[], None]] = queue.SimpleQueue()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("Proxy Manager")
        self.root.geometry("500x730")
        self.root.minsize(460, 690)
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)
        self.root.report_callback_exception = self._on_tk_error
        if ensure_icon_file():
            self.root.iconbitmap(str(ICON_PATH))

        self.active_proxy_type = self.settings["proxy_type"]
        self.proxy_type_var = ctk.StringVar(value=PROXY_TYPE_LABELS[self.active_proxy_type])
        self.show_password_var = ctk.BooleanVar(value=False)
        self.route_mode_var = ctk.StringVar(value=ROUTE_MODE_LABELS[self.settings["route_mode"]])
        # Which checkboxes the program list shows: what goes through the proxy ("apps")
        # or the exceptions of the "all except the selected" mode ("except").
        self.list_mode = "except" if self.settings["route_mode"] == "except" else "apps"
        seed_exceptions(self.settings)
        self._build_ui()
        self._show_profile(self.active_proxy_type)
        self._update_app_widgets()

        # A sing-box left by a crashed instance is picked up, a stale PID file is removed.
        self.manager.reap_exited()
        self.running = self.manager.is_running()
        self._start_tray()
        self._update_state()
        if instance_event:
            threading.Thread(
                target=self._wait_for_show_requests, args=(instance_event,), daemon=True
            ).start()
        self.root.after(100, self._process_ui_calls)
        self.root.after(STATUS_POLL_MS, self._poll_status)
        self._load_kill_switch()
        if self.running:
            self._show_message("sing-box уже был запущен — подключение подхвачено.")
            self.check_ip()
        self.root.mainloop()

    @property
    def busy(self) -> bool:
        return self.operations > 0

    @property
    def blocked(self) -> bool:
        """sing-box is not running, but the kill switch keeps the programs off the internet."""
        return not self.running and self.manager.kill_switch.armed

    @property
    def can_disconnect(self) -> bool:
        return (self.running or self.blocked) and not self.busy

    def _build_ui(self) -> None:
        ctk.CTkLabel(
            self.root, text="PROXY MANAGER",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=(14, 0))

        self.status_label = ctk.CTkLabel(
            self.root, text="", font=ctk.CTkFont(size=16, weight="bold")
        )
        self.status_label.pack(pady=(4, 0))
        self.endpoint_label = ctk.CTkLabel(self.root, text="", text_color="gray", height=18)
        self.endpoint_label.pack()

        ctk.CTkSegmentedButton(
            self.root,
            values=list(PROXY_TYPE_LABELS.values()),
            variable=self.proxy_type_var,
            command=self._on_proxy_type_changed,
            height=32
        ).pack(fill="x", padx=PAD_X, pady=(8, 0))

        host_cell, port_cell = self._form_row(("Сервер: IP или домен", 3), ("Порт", 1))
        self.host_entry = self._entry(host_cell, placeholder="или вставьте host:port:логин:пароль")
        self.port_entry = self._entry(port_cell)
        for sequence in ("<FocusOut>", "<Return>"):
            self.host_entry.bind(sequence, self._apply_proxy_string)

        user_cell, password_cell = self._form_row(("Логин", 1), ("Пароль", 1))
        self.user_entry = self._entry(user_cell)
        self.password_entry = self._entry(password_cell, show="•")
        ctk.CTkCheckBox(
            password_cell, text="показать", variable=self.show_password_var,
            command=self._toggle_password, width=70, height=18,
            checkbox_width=14, checkbox_height=14, border_width=2,
            font=ctk.CTkFont(size=11)
        ).place(relx=1.0, y=1, anchor="ne")
        self.profile_entries = {
            "host": self.host_entry,
            "port": self.port_entry,
            "username": self.user_entry,
            "password": self.password_entry
        }

        ctk.CTkSegmentedButton(
            self.root,
            values=list(ROUTE_MODE_LABELS.values()),
            variable=self.route_mode_var,
            command=self._on_route_mode_changed,
            height=32
        ).pack(fill="x", padx=PAD_X, pady=(12, 0))

        # The whole computer mode has no program list and disables these.
        self.app_widgets: list[Any] = []
        self.program_widgets: list[Any] = []
        self.program_vars: list[ctk.BooleanVar] = []

        header = ctk.CTkFrame(self.root, fg_color="transparent")
        header.pack(fill="x", padx=PAD_X, pady=(8, 0))
        self.programs_label = ctk.CTkLabel(header, text="", anchor="w", height=26)
        self.programs_label.pack(side="left", padx=4)
        add_button = ctk.CTkButton(
            header, text="+ Добавить программы", height=26, width=160,
            fg_color="#444b59", hover_color="#343a46",
            command=self.open_app_picker
        )
        add_button.pack(side="right")
        self.app_widgets.append(add_button)

        # Two columns: the built-in programs first, then the ones added by the user.
        self.programs_frame = ctk.CTkScrollableFrame(self.root, height=104)
        # The scrollbar has a minimal length of its own that would stretch the short list.
        self.programs_frame._scrollbar.configure(height=0)
        self.programs_frame.pack(fill="x", padx=PAD_X, pady=(4, 0))
        self.programs_frame.grid_columnconfigure((0, 1), weight=1, uniform="programs")
        self.app_vars: dict[str, ctk.BooleanVar] = {}
        for index, (key, title) in enumerate(APP_PRESETS.items()):
            var = ctk.BooleanVar(value=self._preset_flags()[key])
            checkbox = self._program_checkbox(self.programs_frame, title, var)
            checkbox.grid(row=index // 2, column=index % 2, sticky="w", padx=4, pady=3)
            self.app_widgets.append(checkbox)
            self.app_vars[key] = var

        self.kill_switch_var = ctk.BooleanVar(value=self.settings["kill_switch"])
        self.kill_switch_box = ctk.CTkCheckBox(
            self.root, text="Kill switch: без прокси эти программы без интернета",
            variable=self.kill_switch_var, onvalue=True, offvalue=False,
            command=self._on_apps_changed
        )
        self.kill_switch_box.pack(fill="x", padx=PAD_X + 4, pady=(8, 0))

        self.games_direct_var = ctk.BooleanVar(value=self.settings["games_direct"])
        ctk.CTkCheckBox(
            self.root, text="Игры Steam (Dota 2, CS2) напрямую, мимо туннеля",
            variable=self.games_direct_var, onvalue=True, offvalue=False,
            command=self._on_games_direct_changed
        ).pack(fill="x", padx=PAD_X + 4, pady=(6, 0))
        self._render_programs()

        buttons = ctk.CTkFrame(self.root, fg_color="transparent")
        buttons.pack(fill="x", padx=PAD_X, pady=(12, 0))
        buttons.grid_columnconfigure((0, 1), weight=1, uniform="buttons")
        self.connect_button = ctk.CTkButton(
            buttons, text="ПОДКЛЮЧИТЬ", height=42,
            fg_color="#168b52", hover_color="#116b3e",
            command=self.connect
        )
        self.connect_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.disconnect_button = ctk.CTkButton(
            buttons, text="ОТКЛЮЧИТЬ", height=42,
            fg_color="#a83232", hover_color="#842727",
            command=self.disconnect
        )
        self.disconnect_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        self.ip_label = ctk.CTkLabel(
            self.root, text="Внешний IP: ещё не проверен",
            font=ctk.CTkFont(size=14)
        )
        self.ip_label.pack(pady=(14, 4))

        ip_buttons = ctk.CTkFrame(self.root, fg_color="transparent")
        ip_buttons.pack()
        ctk.CTkButton(
            ip_buttons, text="Проверить внешний IP", height=30,
            fg_color="#444b59", hover_color="#343a46",
            command=self.check_ip
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            ip_buttons, text="Открыть лог", height=30, width=110,
            fg_color="#444b59", hover_color="#343a46",
            command=self.open_log
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            ip_buttons, text="Для iPhone", height=30, width=100,
            fg_color="#444b59", hover_color="#343a46",
            command=self.export_iphone_profile
        ).pack(side="left", padx=4)

        # A read-only text box: long errors stay readable and can be copied.
        self.message_box = ctk.CTkTextbox(
            self.root, height=70, wrap="word", border_width=0,
            fg_color="transparent", text_color="gray", font=ctk.CTkFont(size=12)
        )
        self.message_box.tag_config("center", justify="center")
        self.message_box.pack(fill="both", expand=True, padx=PAD_X - 6, pady=(10, 8))
        self._show_message("Окно можно закрыть — программа останется в трее.")

    def _form_row(self, *cells: tuple[str, int]) -> list[ctk.CTkFrame]:
        """A row of labelled cells; the number is the share of the row width."""
        row = ctk.CTkFrame(self.root, fg_color="transparent")
        row.pack(fill="x", padx=PAD_X, pady=(8, 0))
        frames = []
        for column, (title, weight) in enumerate(cells):
            row.grid_columnconfigure(column, weight=weight, uniform="cells")
            cell = ctk.CTkFrame(row, fg_color="transparent")
            cell.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 10, 0))
            ctk.CTkLabel(cell, text=title, anchor="w", height=20).pack(fill="x", padx=4)
            frames.append(cell)
        return frames

    @staticmethod
    def _entry(parent: Any, placeholder: str | None = None, show: str | None = None) -> ctk.CTkEntry:
        entry = ctk.CTkEntry(parent, height=34, placeholder_text=placeholder, show=show)
        entry.pack(fill="x")
        return entry

    @staticmethod
    def _set_entry(entry: ctk.CTkEntry, value: str) -> None:
        entry.delete(0, "end")
        if value:
            entry.insert(0, value)

    def _toggle_password(self) -> None:
        self.password_entry.configure(show="" if self.show_password_var.get() else "•")

    def _store_current_profile(self) -> None:
        port = self.port_entry.get().strip()
        self.settings["profiles"][self.active_proxy_type] = {
            "host": self.host_entry.get().strip(),
            "port": int(port) if port.isdigit() else port,
            "username": self.user_entry.get().strip(),
            "password": self.password_entry.get()
        }
        self.settings["proxy_type"] = self.active_proxy_type

    def _preset_flags(self) -> dict[str, bool]:
        """The checkboxes of the built-in programs for what the list shows now."""
        return self.settings["excluded_apps" if self.list_mode == "except" else "apps"]

    def _route_mode(self) -> str:
        label = self.route_mode_var.get()
        return next((mode for mode, text in ROUTE_MODE_LABELS.items() if text == label), "apps")

    def _program_checkbox(self, parent: Any, title: str, var: ctk.BooleanVar) -> ctk.CTkCheckBox:
        # A column fits about 19 characters next to the remove button.
        return ctk.CTkCheckBox(
            parent, text=title if len(title) <= 19 else title[:18] + "…", variable=var,
            onvalue=True, offvalue=False, width=0,
            checkbox_width=20, checkbox_height=20,
            command=self._on_apps_changed
        )

    def _render_programs(self) -> None:
        """Shows the programs added by the user after the built-in ones."""
        for widget in self.program_rows:
            widget.destroy()
        self.program_rows, self.program_widgets, self.program_vars = [], [], []
        for index, program in enumerate(self.settings["programs"]):
            cell = len(APP_PRESETS) + index
            row = ctk.CTkFrame(self.programs_frame, fg_color="transparent")
            row.grid(row=cell // 2, column=cell % 2, sticky="ew", padx=4, pady=3)
            var = ctk.BooleanVar(value=program[PROGRAM_FLAGS[self.list_mode]])
            checkbox = self._program_checkbox(row, program["title"], var)
            checkbox.pack(side="left")
            remove_button = ctk.CTkButton(
                row, text="✕", width=22, height=20,
                fg_color="transparent", hover_color="#842727", text_color="gray",
                command=lambda index=index: self._remove_program(index)
            )
            remove_button.pack(side="right")
            self.program_rows.append(row)
            self.program_widgets += [checkbox, remove_button]
            self.program_vars.append(var)
        self._update_app_widgets()

    def _remove_program(self, index: int) -> None:
        self._store_apps()
        removed = self.settings["programs"].pop(index)
        self._render_programs()
        self._save_settings()
        message = f"«{removed['title']}» убрана из списка."
        if self.running:
            message += " Нажмите «Переподключить», чтобы применить."
        self._show_message(message)

    def _update_app_widgets(self) -> None:
        mode = self._route_mode()
        state = "disabled" if mode == "all" else "normal"
        for widget in self.app_widgets + self.program_widgets:
            widget.configure(state=state)
        # The filters list programs, so the kill switch only works for the selected ones.
        self.kill_switch_box.configure(state="normal" if mode == "apps" else "disabled")
        self.programs_label.configure(
            text="Напрямую, мимо прокси" if self.list_mode == "except" else "Программы через прокси"
        )

    def _show_list_mode(self, list_mode: str) -> None:
        """Switches the list between the proxied programs and the exceptions."""
        if list_mode == self.list_mode:
            return
        self._store_apps()
        self.list_mode = list_mode
        for key, var in self.app_vars.items():
            var.set(self._preset_flags()[key])
        self._render_programs()

    def _store_apps(self) -> None:
        self.settings["route_mode"] = self._route_mode()
        self._preset_flags().update({key: var.get() for key, var in self.app_vars.items()})
        for program, var in zip(self.settings["programs"], self.program_vars):
            program[PROGRAM_FLAGS[self.list_mode]] = var.get()
        self.settings["kill_switch"] = self.kill_switch_var.get()
        self.settings["games_direct"] = self.games_direct_var.get()

    def _save_settings(self) -> None:
        self._store_current_profile()
        self._store_apps()
        try:
            save_settings(self.settings)
        except OSError as exc:
            self._show_message(f"Не удалось сохранить настройки: {exc}")

    def _on_apps_changed(self) -> None:
        self._save_settings()
        if self.running:
            self._show_message(
                "Список программ изменён. Нажмите «Переподключить», чтобы применить."
            )

    def _on_route_mode_changed(self, _value: str) -> None:
        mode = self._route_mode()
        if mode in PROGRAM_FLAGS:
            self._show_list_mode(mode)
        self._update_app_widgets()
        self._save_settings()
        if mode == "all":
            message = (
                "Через прокси пойдёт весь интернет-трафик компьютера, кроме локальной сети. "
                "Kill switch в этом режиме не работает: если sing-box упадёт, трафик пойдёт напрямую."
            )
            if self.active_proxy_type == "http":
                message += " HTTP-прокси не передаёт UDP: звонки и часть игр работать не будут."
        elif mode == "except":
            message = (
                "Через прокси пойдёт весь компьютер, кроме отмеченных в списке программ: они "
                "ходят напрямую. Kill switch в этом режиме не работает."
            )
            if self.active_proxy_type == "http":
                message += (
                    " HTTP-прокси не передаёт UDP: звонки и игры будут работать только "
                    "в программах из списка."
                )
        else:
            message = "Через прокси пойдут только выбранные программы."
        if self.running:
            message += " Нажмите «Переподключить», чтобы применить."
        self._show_message(message)

    def _on_games_direct_changed(self) -> None:
        self._save_settings()
        if self.games_direct_var.get():
            message = "Dota 2 и CS2 будут ходить к серверам Valve напрямую, мимо туннеля."
        else:
            message = "Трафик игр Steam снова пойдёт через туннель, как у остальных программ."
        if self.running:
            message += " Нажмите «Переподключить», чтобы применить."
        self._show_message(message)

    def open_app_picker(self) -> None:
        if self.picker is not None and self.picker.winfo_exists():
            self.picker.lift()
            self.picker.focus_force()
            return
        self.picker = AppPicker(self)

    def set_programs(self, programs: list[dict[str, Any]]) -> None:
        self.settings["programs"] = programs
        self._render_programs()
        self._save_settings()
        if self.running:
            message = "Список программ изменён. Нажмите «Переподключить», чтобы применить."
        else:
            message = "Список программ сохранён: он останется и при следующих запусках."
        self._show_message(message)

    def _show_profile(self, proxy_type: str) -> None:
        profile = self.settings["profiles"][proxy_type]
        for key, entry in self.profile_entries.items():
            self._set_entry(entry, str(profile.get(key, "")))

    def _on_proxy_type_changed(self, value: str) -> None:
        proxy_type = "http" if value == PROXY_TYPE_LABELS["http"] else "socks"
        if proxy_type == self.active_proxy_type:
            return
        self._store_current_profile()
        self.active_proxy_type = proxy_type
        self._show_profile(proxy_type)
        self._save_settings()
        if self.running:
            self._show_message("Тип прокси изменён. Нажмите «Переподключить», чтобы применить.")

    def _apply_proxy_string(self, _event: Any = None) -> None:
        fields = parse_proxy_string(self.host_entry.get())
        if fields is None:
            return
        proxy_type = fields.pop("proxy_type", self.active_proxy_type)
        if proxy_type != self.active_proxy_type:
            # The pasted line belongs to the other profile: leave the current one as saved.
            self.active_proxy_type = proxy_type
            self.proxy_type_var.set(PROXY_TYPE_LABELS[proxy_type])
            self._show_profile(proxy_type)
        for key, value in fields.items():
            self._set_entry(self.profile_entries[key], value)
        self._save_settings()

    def _get_proxy_fields(self) -> dict[str, Any]:
        """The proxy server from the form; ValueError says what is wrong."""
        self._apply_proxy_string()
        host = self.host_entry.get().strip().strip("[]")
        if not host:
            raise ValueError("Укажите IP-адрес или домен прокси-сервера.")
        if any(char in host for char in " /\\@") or (":" in host and not is_ipv6(host)):
            raise ValueError(
                "Адрес прокси указан неверно: в поле «Сервер» нужен только IP-адрес или домен."
            )

        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            port = 0
        if not 1 <= port <= 65535:
            raise ValueError("Порт должен быть числом от 1 до 65535.")
        return {
            "proxy_type": self.active_proxy_type,
            "host": host,
            "port": port,
            "username": self.user_entry.get().strip(),
            "password": self.password_entry.get()
        }

    def _get_form_data(self) -> dict[str, Any]:
        proxy = self._get_proxy_fields()
        route_mode = self._route_mode()
        self._store_apps()
        targets = AppTargets()
        excluded = AppTargets()
        if route_mode == "apps":
            targets = resolve_apps(self.settings["apps"], programs_text(self.settings["programs"]))
            if not targets:
                raise ValueError(
                    "Выберите хотя бы одну программу, которая будет работать через прокси."
                )
        elif route_mode == "except":
            excluded = resolve_apps(
                self.settings["excluded_apps"], programs_text(self.settings["programs"], "excluded")
            )

        return {
            **proxy,
            "route_mode": route_mode,
            "targets": targets,
            "app_patterns": targets.regex_patterns(),
            "excluded_patterns": excluded.regex_patterns(),
            # The filters list programs, so they cannot cover the whole computer.
            "kill_switch": route_mode == "apps" and self.kill_switch_var.get(),
            "games_direct": self.games_direct_var.get(),
            "verbose_log": self.settings["verbose_log"]
        }

    def _run_operation(
        self,
        busy_text: str,
        task: Callable[[], tuple[bool, str]],
        on_done: Callable[[bool, str], None]
    ) -> None:
        self.operations += 1
        self.busy_text = busy_text
        self._update_state()

        def worker() -> None:
            try:
                ok, message = task()
            except Exception as exc:
                log_app_error(traceback.format_exc())
                ok, message = False, f"Внутренняя ошибка: {exc}"
            self._call_in_ui(lambda: self._operation_finished(ok, message, on_done))

        threading.Thread(target=worker, daemon=True).start()

    def _operation_finished(
        self, ok: bool, message: str, on_done: Callable[[bool, str], None]
    ) -> None:
        self.operations -= 1
        self.running = self.manager.is_running()
        self._update_state()
        on_done(ok, message)

    def connect(self) -> None:
        if self.busy or self.quitting:
            return
        try:
            data = self._get_form_data()
        except ValueError as exc:
            self._report(str(exc))
            return

        self._save_settings()
        reconnect = self.running

        def done(ok: bool, message: str) -> None:
            self._report(message)
            if ok:
                self.check_ip()
                if self.manager.kill_switch.armed:
                    self._follow_programs(scan=True)
            else:
                self._reset_ip_label()

        self._run_operation(
            "Переподключение..." if reconnect else "Подключение...",
            lambda: self.manager.connect(data), done
        )

    def disconnect(self) -> None:
        if self.busy or self.quitting:
            return

        def done(ok: bool, message: str) -> None:
            self._report(message)
            if ok:
                self._reset_ip_label()

        self._run_operation("Отключение...", self.manager.disconnect, done)

    def check_ip(self) -> None:
        self.ip_check_id += 1
        check_id = self.ip_check_id
        self.ip_label.configure(text="Внешний IP: проверяем...")
        # This app itself is not in the proxied list, so the proxy IP is checked
        # through the local sing-box inbound.
        proxy_url = self.manager.ip_check_proxy()
        # With the whole computer proxied this app goes through the TUN like any other.
        active_mode = self.manager.active_mode()

        def worker() -> None:
            direct_ip = fetch_external_ip(None)
            if active_mode == "all":
                text = f"Весь компьютер: {direct_ip}"
            elif active_mode == "except":
                text = f"Все, кроме выбранных: {direct_ip}\nВыбранные идут напрямую, с вашим IP"
            elif proxy_url:
                text = (
                    f"Выбранные программы: {fetch_external_ip(proxy_url)}\n"
                    f"Остальные программы: {direct_ip}"
                )
            else:
                text = f"Внешний IP: {direct_ip}"
            self._call_in_ui(lambda: self._show_ip(check_id, text))

        threading.Thread(target=worker, daemon=True).start()

    def _show_ip(self, check_id: int, text: str) -> None:
        # A check started before a reconnect or disconnect is outdated.
        if check_id == self.ip_check_id:
            self.ip_label.configure(text=text)

    def _reset_ip_label(self) -> None:
        self.ip_check_id += 1
        self.ip_label.configure(text="Внешний IP: ещё не проверен")

    def open_log(self) -> None:
        try:
            os.startfile(LOG_PATH if LOG_PATH.exists() else LOG_DIR)
        except OSError as exc:
            self._show_message(f"Не удалось открыть лог: {exc}")

    def export_iphone_profile(self) -> None:
        """Saves a sing-box profile for iPhone with the proxy from the form."""
        try:
            proxy = self._get_proxy_fields()
        except ValueError as exc:
            self._show_message(str(exc))
            return
        text = json.dumps(self.manager.build_iphone_config(proxy), indent=2, ensure_ascii=False)

        folders = desktop_folders()
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Сохранить профиль для iPhone",
            initialdir=str(folders[0]) if folders else None,
            initialfile="proxy-iphone.json",
            defaultextension=".json",
            filetypes=[("Профиль sing-box", "*.json")]
        )
        if not path:
            return
        try:
            Path(path).write_text(text, encoding="utf-8")
            if BIN_PATH.is_file():
                check = subprocess.run(
                    [str(BIN_PATH), "check", "--disable-color", "-c", path],
                    stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8",
                    errors="replace", timeout=20, cwd=str(BASE_DIR), creationflags=NO_WINDOW
                )
                if check.returncode != 0:
                    detail = strip_ansi(check.stderr or check.stdout).strip()
                    self._show_message(f"Профиль не прошёл проверку sing-box:\n{detail}")
                    return
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._show_message(f"Не удалось сохранить профиль: {exc}")
            return

        # Telegram on the phone takes the text as it is; the file goes through the Files app.
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._show_message(f"Профиль для iPhone сохранён: {path}\nТекст профиля скопирован в буфер обмена.")
        warning = (
            "\n\nДля HTTP-прокси звонки (FaceTime, WhatsApp, Telegram) и часть игр работать "
            "не будут: HTTP-прокси не передаёт UDP."
            if proxy["proxy_type"] == "http" else ""
        )
        messagebox.showinfo(
            "Профиль для iPhone",
            f"Профиль сохранён в файл {Path(path).name} и скопирован в буфер обмена.\n\n"
            "1. Установите на iPhone бесплатное приложение sing-box MT из App Store.\n"
            "2. Отправьте профиль себе в Telegram, в «Избранное»: вставьте текст (Ctrl+V) "
            "или перетащите файл.\n"
            "3. В sing-box MT создайте новый профиль типа Local: вставьте в редактор "
            "скопированный из Telegram текст или импортируйте файл, сохранённый в «Файлы».\n"
            "4. Выберите профиль и включите его, разрешите добавить конфигурацию VPN.\n\n"
            "Через прокси пойдёт весь телефон, кроме локальной сети. В профиле записан пароль "
            "от прокси: после импорта удалите сообщение в Telegram и файл." + warning,
            parent=self.root
        )

    def _show_message(self, message: str) -> None:
        self.message_box.configure(state="normal")
        self.message_box.delete("1.0", "end")
        self.message_box.insert("1.0", message.strip(), "center")
        self.message_box.configure(state="disabled")

    def _report(self, message: str, force_notify: bool = False) -> None:
        """Shows the message in the window and, if the window is hidden, in the tray."""
        self._show_message(message)
        if force_notify or self.root.state() not in {"normal", "zoomed"}:
            self._notify(message.strip().splitlines()[0] if message.strip() else message)

    def _notify(self, message: str) -> None:
        if self.tray is None:
            return
        try:
            self.tray.notify(message[:250], "Proxy Manager")
        except Exception:
            pass

    def _update_state(self) -> None:
        if self.busy:
            status, color, tray_color = self.busy_text, COLOR_BUSY, COLOR_BUSY
        elif self.running:
            status, color, tray_color = "Подключено", COLOR_CONNECTED, COLOR_CONNECTED
        elif self.blocked:
            status, color, tray_color = "Нет прокси — программы заблокированы", \
                COLOR_DISCONNECTED, COLOR_DISCONNECTED
        else:
            status, color, tray_color = "Отключено", COLOR_DISCONNECTED, COLOR_TRAY_OFF

        self.status_label.configure(text=f"● {status}", text_color=color)
        endpoint = self.manager.active_endpoint() if self.running and not self.busy else None
        self.endpoint_label.configure(text=endpoint or "")
        self.connect_button.configure(
            text="ПЕРЕПОДКЛЮЧИТЬ" if self.running else "ПОДКЛЮЧИТЬ",
            state="disabled" if self.busy else "normal"
        )
        self.disconnect_button.configure(
            state="normal" if self.can_disconnect else "disabled"
        )
        if self.tray:
            self.tray.icon = make_icon_image(tray_color)
            self.tray.title = f"Proxy Manager: {status.lower()}"
            self.tray.update_menu()

    def _poll_status(self) -> None:
        if self.closing:
            return
        if not self.busy:
            reason = self.manager.reap_exited()
            running = self.manager.is_running()
            if running != self.running:
                self.running = running
                self._update_state()
                if not running:
                    self._reset_ip_label()
                    if self.manager.kill_switch.armed:
                        tail = (
                            "Kill switch заблокировал интернет выбранным программам. "
                            "Нажмите «Подключить», чтобы вернуть прокси, или «Отключить», "
                            "чтобы программы снова ходили напрямую."
                        )
                    else:
                        tail = "Трафик программ снова идёт напрямую."
                    self._report(
                        f"{reason or 'sing-box остановлен.'}\n{tail}", force_notify=True
                    )
            if self.manager.kill_switch.armed and time.monotonic() >= self.next_follow:
                self._follow_programs()
        self.root.after(STATUS_POLL_MS, self._poll_status)

    def _follow_programs(self, scan: bool = False) -> None:
        """Covers newly started programs of the selected folders by the kill switch."""
        self.next_follow = time.monotonic() + KILL_SWITCH_POLL_S
        if self.following or not self.manager.kill_switch.armed:
            return
        self.following = True

        def worker() -> None:
            try:
                self.manager.follow_programs(scan=scan)
            except Exception:
                log_app_error(traceback.format_exc())
            finally:
                self.following = False

        threading.Thread(target=worker, daemon=True).start()

    def _load_kill_switch(self) -> None:
        """Reads the kill switch state from WFP, e.g. after a crash or a reboot."""
        def worker() -> None:
            try:
                self.manager.kill_switch.refresh()
                if self.manager.kill_switch.armed and self.manager.targets is None:
                    self.manager.targets = resolve_apps(
                        self.settings["apps"], programs_text(self.settings["programs"])
                    )
            except Exception:
                log_app_error(traceback.format_exc())
            self._call_in_ui(self._kill_switch_loaded)

        threading.Thread(target=worker, daemon=True).start()

    def _kill_switch_loaded(self) -> None:
        self._update_state()
        if self.blocked:
            self._report(
                "Kill switch включён, а прокси не подключён: выбранные программы без "
                "интернета. Нажмите «Подключить» или «Отключить».",
                force_notify=True
            )

    def _call_in_ui(self, call: Callable[[], None]) -> None:
        # Tk is not thread-safe: other threads hand their work to the main loop.
        self.ui_calls.put(call)

    def _process_ui_calls(self) -> None:
        while not self.closing:
            try:
                call = self.ui_calls.get_nowait()
            except queue.Empty:
                break
            try:
                call()
            except Exception:
                self._on_tk_error(*sys.exc_info())
        if not self.closing:
            self.root.after(100, self._process_ui_calls)

    def _on_tk_error(self, exc_type, exc, tb) -> None:
        log_app_error("".join(traceback.format_exception(exc_type, exc, tb)))
        if not self.closing:
            self._show_message(f"Внутренняя ошибка: {exc}\nПодробности в logs\\app.log.")

    def _wait_for_show_requests(self, event: int) -> None:
        while kernel32.WaitForSingleObject(event, INFINITE) == WAIT_OBJECT_0:
            self._call_in_ui(self.show_window)

    def _start_tray(self) -> None:
        menu = pystray.Menu(
            pystray.MenuItem(
                "Открыть Proxy Manager",
                lambda icon, item: self._call_in_ui(self.show_window),
                default=True
            ),
            pystray.MenuItem(
                lambda item: "Переподключить" if self.running else "Подключить",
                lambda icon, item: self._call_in_ui(self.connect),
                enabled=lambda item: not self.busy
            ),
            pystray.MenuItem(
                "Отключить",
                lambda icon, item: self._call_in_ui(self.disconnect),
                enabled=lambda item: self.can_disconnect
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Выход",
                lambda icon, item: self._call_in_ui(self.quit_app)
            )
        )

        self.tray = pystray.Icon(
            "ProxyManager", make_icon_image(COLOR_TRAY_OFF), "Proxy Manager", menu
        )
        threading.Thread(target=self.tray.run, daemon=True).start()

    def hide_window(self) -> None:
        self._save_settings()
        self.root.withdraw()
        if not self.tray_hint_shown:
            self.tray_hint_shown = True
            self._notify("Proxy Manager работает в трее. Выход — через меню значка.")

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        # Windows does not let a background process steal focus; topmost brings it up anyway.
        self.root.attributes("-topmost", True)
        self.root.after(200, lambda: self.root.attributes("-topmost", False))
        self.root.focus_force()

    def quit_app(self) -> None:
        if self.quitting:
            return
        self.quitting = True
        self._save_settings()

        def done(ok: bool, message: str) -> None:
            if not ok:
                self.quitting = False
                self._report(message)
                self.show_window()
                return
            self.closing = True
            if self.tray:
                self.tray.stop()
            self.root.destroy()

        # If a connection is being made, disconnect() waits for it and then stops sing-box.
        self._run_operation("Отключение...", self.manager.disconnect, done)


class AppPicker(ctk.CTkToplevel):
    """A window to add programs to the list: from the desktop, an .exe or a folder."""

    def __init__(self, app: ProxyApp) -> None:
        super().__init__(app.root)
        self.app = app
        self.rows: list[tuple[PickerRow, ctk.BooleanVar]] = []
        self.title("Добавить программы")
        self.geometry(f"440x520+{app.root.winfo_x() + 30}+{app.root.winfo_y() + 60}")
        self.minsize(380, 360)
        self.transient(app.root)
        if ICON_PATH.is_file():
            self.iconbitmap(str(ICON_PATH))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(side="bottom", fill="x", padx=16, pady=(6, 14))
        ctk.CTkButton(
            buttons, text="Файл...", width=80,
            fg_color="#444b59", hover_color="#343a46",
            command=self._browse
        ).pack(side="left")
        ctk.CTkButton(
            buttons, text="Папка...", width=80,
            fg_color="#444b59", hover_color="#343a46",
            command=self._browse_folder
        ).pack(side="left", padx=(6, 0))
        ctk.CTkButton(
            buttons, text="Готово", width=90,
            fg_color="#168b52", hover_color="#116b3e",
            command=self._apply
        ).pack(side="right")
        ctk.CTkButton(
            buttons, text="Отмена", width=90,
            fg_color="#444b59", hover_color="#343a46",
            command=self.destroy
        ).pack(side="right", padx=(0, 6))

        ctk.CTkLabel(
            self, text_color="gray", wraplength=400, justify="left", anchor="w",
            text="Это программы с рабочего стола. Игр Steam и других лаунчеров (.url) и "
                 "приложений из Microsoft Store здесь нет: для них нажмите «Файл...» и укажите "
                 ".exe. «Папка...» добавляет все программы из папки."
        ).pack(side="bottom", fill="x", padx=18, pady=(6, 0))

        self.list_frame = ctk.CTkScrollableFrame(self)
        self.list_frame.pack(fill="both", expand=True, padx=16, pady=(14, 0))
        self.status_label = ctk.CTkLabel(self.list_frame, text="Читаем ярлыки...", text_color="gray")
        self.status_label.pack(pady=20)

        self.after(200, self._grab)
        app._store_apps()
        existing = [dict(program) for program in app.settings["programs"]]
        self.existing = {os.path.normpath(program["path"]).lower(): program for program in existing}
        selected = dict(app._preset_flags())
        threading.Thread(target=self._load, args=(existing, selected), daemon=True).start()

    def _grab(self) -> None:
        try:
            self.grab_set()
            self.focus_force()
        except TclError:
            pass

    def _load(self, existing: list[dict[str, Any]], selected: dict[str, bool]) -> None:
        try:
            try:
                covered = resolve_apps(selected, "")
            except ValueError:
                covered = AppTargets()
            for program in existing:
                if is_path_entry(program["path"]) and Path(program["path"]).is_dir():
                    covered.add_dir(program["path"])
            rows = picker_rows(existing, find_desktop_apps(), covered)
        except Exception:
            log_app_error(traceback.format_exc())
            rows = picker_rows(existing, [], AppTargets())
        self.app._call_in_ui(lambda: self._show_rows(rows))

    def _show_rows(self, rows: list[PickerRow]) -> None:
        if not self.winfo_exists():
            return
        self.status_label.pack_forget()
        if not rows:
            self.status_label.configure(text="На рабочем столе не найдено программ.")
            self.status_label.pack(pady=20)
        for row in rows:
            self._add_row(row)

    def _add_row(self, row: PickerRow) -> None:
        self.status_label.pack_forget()
        var = ctk.BooleanVar(value=row.checked)
        name = Path(row.entry).name or row.entry
        details = "уже в списке" if row.covered else name
        text = row.title if row.title.lower() == name.lower() else f"{row.title}  ({details})"
        ctk.CTkCheckBox(
            self.list_frame, text=text, variable=var,
            onvalue=True, offvalue=False,
            state="disabled" if row.covered else "normal"
        ).pack(fill="x", padx=6, pady=4)
        self.rows.append((row, var))

    def _browse(self) -> None:
        folders = desktop_folders()
        paths = filedialog.askopenfilenames(
            parent=self,
            title="Выберите программы",
            initialdir=str(folders[0]) if folders else None,
            filetypes=[("Программы и ярлыки", ("*.exe", "*.lnk"))]
        )
        known = {os.path.normpath(row.entry).lower(): var for row, var in self.rows}
        shortcuts = read_shortcuts([
            os.path.normpath(path) for path in paths if path.lower().endswith(".lnk")
        ])
        for path in map(os.path.normpath, paths):
            program: str | None = path
            if path.lower().endswith(".lnk"):
                program = shortcut_program(*shortcuts.get(path.lower(), ("", "")))
            if program is None:
                self.app._show_message(f"Ярлык не ведёт к программе: {Path(path).name}")
                continue
            existing = known.get(os.path.normpath(program).lower())
            if existing is not None:
                existing.set(True)
                continue
            self._add_row(PickerRow(program, Path(path).stem, True, False))

    def _browse_folder(self) -> None:
        folder = filedialog.askdirectory(parent=self, title="Выберите папку программы")
        if not folder:
            return
        folder = os.path.normpath(folder)
        for row, var in self.rows:
            if os.path.normpath(row.entry).lower() == folder.lower():
                var.set(True)
                return
        self._add_row(PickerRow(folder, f"Папка {Path(folder).name or folder}", True, False))

    def _apply(self) -> None:
        programs: list[dict[str, Any]] = []
        for row, var in self.rows:
            if not var.get() or row.covered:
                continue
            # A program already in the list keeps its own checkboxes; a new one is
            # checked in the list that is shown now.
            known = self.existing.get(os.path.normpath(row.entry).lower())
            if known:
                programs.append(known)
            else:
                add_program(
                    programs, row.entry, row.title,
                    enabled=self.app.list_mode == "apps", excluded=self.app.list_mode == "except"
                )
        self.app.set_programs(programs)
        self.destroy()


def main() -> None:
    if os.name != "nt":
        raise SystemExit("Эта версия Proxy Manager предназначена для Windows.")

    ensure_dirs()
    install_error_logging()

    try:
        if signal_running_instance():
            return
        if not is_admin():
            relaunch_as_admin()
            return

        instance_event = create_instance_event()
        if instance_event is None:
            return

        # Own taskbar group and icon instead of the ones of python.exe.
        shell32.SetCurrentProcessExplicitAppUserModelID("ProxyManager")
        ProxyApp(instance_event)
    except Exception:
        log_app_error(traceback.format_exc())
        show_message_box(
            "Proxy Manager завершился с ошибкой. Подробности в logs\\app.log.", error=True
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
