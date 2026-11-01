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
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
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
START_TIMEOUT = 5
STATUS_POLL_MS = 1500
INSTANCE_EVENT_NAME = "Local\\ProxyManagerShowWindow"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")

PROXY_TYPE_LABELS = {"socks": "SOCKS5", "http": "HTTP"}
PROXY_SCHEMES = {"socks": "socks", "socks5": "socks", "socks5h": "socks", "http": "http"}

PAD_X = 24
COLOR_CONNECTED = "#22c77a"
COLOR_DISCONNECTED = "#ef5350"
COLOR_BUSY = "#ffb74d"
COLOR_ICON = "#168bdb"
COLOR_TRAY_OFF = "#7a8394"

# Case-insensitive Go regexps matched against the full path of the process.
APP_PRESETS: dict[str, tuple[str, list[str]]] = {
    "chrome": ("Google Chrome", [r"(?i)\\chrome\.exe$"]),
    # Claude Code, Codex and other extensions run their own executables from the extensions folder.
    "vscode": ("VS Code", [r"(?i)\\code\.exe$", r"(?i)\\\.vscode\\extensions\\"]),
    # Hermes.exe is only the UI: LLM requests come from the backend run by Hermes' own
    # Python, which, like its bundled node/chromium/git, lives in %LOCALAPPDATA%\hermes.
    "hermes": ("Hermes", [r"(?i)\\AppData\\Local\\hermes\\"]),
}

DEFAULT_SETTINGS = {
    "proxy_type": "socks",
    "apps": {key: True for key in APP_PRESETS},
    "custom_apps": "",
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

    if isinstance(data.get("custom_apps"), str):
        settings["custom_apps"] = data["custom_apps"]
    if isinstance(data.get("verbose_log"), bool):
        settings["verbose_log"] = data["verbose_log"]
    return settings


def save_settings(data: dict[str, Any]) -> None:
    # For this starter project the credentials are stored locally in settings.json.
    # Restrict access to this file to your Windows account before using it on a shared PC.
    temp_path = SETTINGS_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
    os.replace(temp_path, SETTINGS_PATH)


def parse_custom_apps(text: str) -> list[str]:
    names: dict[str, str] = {}
    for item in re.split(r"[,;\n]", text):
        name = Path(item.strip().strip('"')).name
        if not name:
            continue
        if not name.lower().endswith(".exe"):
            name += ".exe"
        names.setdefault(name.lower(), name)
    return list(names.values())


def build_app_patterns(apps: dict[str, bool], custom_apps: str) -> list[str]:
    patterns = [
        pattern
        for key, (_, preset_patterns) in APP_PRESETS.items()
        if apps.get(key)
        for pattern in preset_patterns
    ]
    patterns += [
        r"(?i)\\" + re.escape(name) + "$"
        for name in parse_custom_apps(custom_apps)
    ]
    return patterns


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


class ProxyManager:
    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.log_offset = 0
        self.lock = threading.Lock()

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
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
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

        app_patterns = data["app_patterns"]
        rules: list[dict[str, Any]] = [
            {
                "inbound": [IP_CHECK_INBOUND_TAG],
                "action": "route",
                "outbound": "proxy"
            }
        ]
        if proxy_type == "http":
            rules += [
                {
                    "process_path_regex": app_patterns,
                    "ip_version": 6,
                    "action": "reject"
                },
                {
                    "process_path_regex": app_patterns,
                    "network": "udp",
                    "action": "reject"
                }
            ]
        rules.append({
            "process_path_regex": app_patterns,
            "action": "route",
            "outbound": "proxy"
        })

        return {
            "log": {
                # "info" logs every connection: about 10 MB per hour of browsing.
                "level": "info" if data.get("verbose_log") else "warn",
                "timestamp": True
            },
            "dns": {
                # DNS servers of the physical adapter, the same as without the proxy.
                "servers": [{"type": "local", "tag": "dns-local"}],
                "final": "dns-local",
                # The TUN has an IPv6 address, so without this apps would try IPv6
                # even when the network has no IPv6 connectivity.
                "strategy": "ipv4_only"
            },
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
                },
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
                "final": "direct"
            }
        }

    def write_config(self, data: dict[str, Any]) -> int:
        ip_check_port = find_free_port()
        CONFIG_PATH.write_text(
            json.dumps(self.build_config(data, ip_check_port), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        return ip_check_port

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
                return f"{kind} · {server}:{outbound.get('server_port')}"
        return None

    def _wait_until_started(self, ip_check_port: int) -> bool:
        # The IP check inbound comes after the TUN, so once it listens the TUN is up.
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", ip_check_port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        time.sleep(0.3)
        return self.process.poll() is None

    def connect(self, data: dict[str, Any]) -> tuple[bool, str]:
        with self.lock:
            if self.is_running():
                return False, "Прокси уже подключён."
            if not BIN_PATH.is_file():
                return False, (
                    "Не найден bin\\sing-box.exe. Скачайте Windows amd64 "
                    "версию sing-box и положите sing-box.exe в папку bin."
                )

            problem = probe_proxy(data)
            if problem:
                return False, problem

            try:
                ip_check_port = self.write_config(data)
                check = subprocess.run(
                    [str(BIN_PATH), "check", "--disable-color", "-c", str(CONFIG_PATH)],
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

                rotate_log()
                # sing-box keeps its own copy of the handle, so ours can be closed at once.
                with LOG_PATH.open("ab") as log:
                    self.log_offset = log.seek(0, os.SEEK_END)
                    self.process = subprocess.Popen(
                        [str(BIN_PATH), "run", "--disable-color", "-c", str(CONFIG_PATH)],
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        cwd=str(BASE_DIR),
                        creationflags=NO_WINDOW
                    )
                PID_PATH.write_text(str(self.process.pid), encoding="ascii")

                if not self._wait_until_started(ip_check_port):
                    self._stop_own_process()
                    return False, "sing-box не запустился.\n" + self._log_tail()

                return True, "Прокси подключён. Проверяем внешний IP..."
            except subprocess.TimeoutExpired:
                return False, "Проверка конфигурации заняла слишком много времени."
            except Exception as exc:
                self._stop_own_process()
                return False, f"Не удалось запустить sing-box: {exc}"

    def _stop_own_process(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._remove_pid_file(self.process.pid)
        self.process = None

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
                    return True, "Прокси отключён."

                pid = self._tracked_pid()
                if pid is None:
                    return True, "Прокси уже отключён."
                if not self._is_singbox_process(pid):
                    self._remove_pid_file(pid)
                    return True, "Запущенный sing-box не найден; файл состояния очищен."
                self._force_stop(pid)
                self._remove_pid_file(pid)
                return True, "Зависший sing-box остановлен; интернет-маршрут восстановлен."
            except Exception as exc:
                return False, f"Не удалось остановить sing-box: {exc}"

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
        self.tray: pystray.Icon | None = None
        self.tray_hint_shown = False
        self.ui_calls: queue.SimpleQueue[Callable[[], None]] = queue.SimpleQueue()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("Proxy Manager")
        self.root.geometry("480x660")
        self.root.minsize(440, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)
        self.root.report_callback_exception = self._on_tk_error
        if ensure_icon_file():
            self.root.iconbitmap(str(ICON_PATH))

        self.active_proxy_type = self.settings["proxy_type"]
        self.proxy_type_var = ctk.StringVar(value=PROXY_TYPE_LABELS[self.active_proxy_type])
        self.show_password_var = ctk.BooleanVar(value=False)
        self._build_ui()
        self._show_profile(self.active_proxy_type)

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
        if self.running:
            self._show_message("sing-box уже был запущен — подключение подхвачено.")
            self.check_ip()
        self.root.mainloop()

    @property
    def busy(self) -> bool:
        return self.operations > 0

    def _build_ui(self) -> None:
        ctk.CTkLabel(
            self.root, text="PROXY MANAGER",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=(14, 0))

        ctk.CTkLabel(
            self.root, text="Трафик выбранных программ через прокси",
            text_color="gray"
        ).pack()

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

        ctk.CTkLabel(self.root, text="Через прокси", anchor="w", height=20).pack(
            fill="x", padx=PAD_X + 4, pady=(12, 2)
        )
        apps_row = ctk.CTkFrame(self.root, fg_color="transparent")
        apps_row.pack(fill="x", padx=PAD_X)
        self.app_vars: dict[str, ctk.BooleanVar] = {}
        for key, (title, _) in APP_PRESETS.items():
            var = ctk.BooleanVar(value=self.settings["apps"][key])
            ctk.CTkCheckBox(
                apps_row, text=title, variable=var,
                onvalue=True, offvalue=False,
                command=self._on_apps_changed
            ).pack(side="left", padx=(4, 12))
            self.app_vars[key] = var

        self.custom_apps_entry = ctk.CTkEntry(
            self.root, height=34,
            placeholder_text="Другие программы через запятую: telegram.exe"
        )
        self.custom_apps_entry.pack(fill="x", padx=PAD_X, pady=(6, 0))
        if self.settings["custom_apps"]:
            self.custom_apps_entry.insert(0, self.settings["custom_apps"])
        for sequence in ("<FocusOut>", "<Return>"):
            self.custom_apps_entry.bind(sequence, self._on_custom_apps_edited)

        buttons = ctk.CTkFrame(self.root, fg_color="transparent")
        buttons.pack(fill="x", padx=PAD_X, pady=(16, 0))
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

    def _selected_apps(self) -> dict[str, bool]:
        return {key: var.get() for key, var in self.app_vars.items()}

    def _store_apps(self) -> None:
        self.settings["apps"] = self._selected_apps()
        self.settings["custom_apps"] = self.custom_apps_entry.get().strip()

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

    def _on_custom_apps_edited(self, _event: Any = None) -> None:
        if self.custom_apps_entry.get().strip() != self.settings["custom_apps"]:
            self._on_apps_changed()

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

    def _get_form_data(self) -> dict[str, Any]:
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

        app_patterns = build_app_patterns(
            self._selected_apps(), self.custom_apps_entry.get()
        )
        if not app_patterns:
            raise ValueError("Выберите хотя бы одну программу, которая будет работать через прокси.")

        return {
            "proxy_type": self.active_proxy_type,
            "host": host,
            "port": port,
            "username": self.user_entry.get().strip(),
            "password": self.password_entry.get(),
            "app_patterns": app_patterns,
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

        def task() -> tuple[bool, str]:
            if reconnect:
                ok, message = self.manager.disconnect()
                if not ok:
                    return ok, message
            return self.manager.connect(data)

        def done(ok: bool, message: str) -> None:
            self._report(message)
            if ok:
                self.check_ip()
            else:
                self._reset_ip_label()

        self._run_operation("Переподключение..." if reconnect else "Подключение...", task, done)

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

        def worker() -> None:
            direct_ip = fetch_external_ip(None)
            if proxy_url:
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
            state="normal" if self.running and not self.busy else "disabled"
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
                    self._report(
                        reason or "sing-box остановлен. Трафик программ снова идёт напрямую.",
                        force_notify=True
                    )
        self.root.after(STATUS_POLL_MS, self._poll_status)

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
                enabled=lambda item: self.running and not self.busy
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
