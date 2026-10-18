"""Decoy services. They annotate replayed events with honeypot response details.

Flow records and honeypot logs already describe what happened on the wire; the decoys
only fill in what a source leaves open (login outcome, HTTP status) and record what the
honeypot would have done (fake SYN-ACK, fake shell). Commands are recorded as text;
nothing is ever executed.
"""
from __future__ import annotations

from collections import Counter
from typing import Optional

from ..config import Settings
from ..schemas import Event

SENSITIVE_HINTS = ("wp-admin", "wp-login", ".env", ".git", "phpmyadmin", "admin.php", "cgi-bin", "passwd",
                   "xmlrpc", "actuator", ".aws", "backup", "config", "shell", "eval", "../", "select%20", "union")


def is_sensitive_path(path: Optional[str]) -> bool:
    p = (path or "").lower()
    return any(h in p for h in SENSITIVE_HINTS)


class Decoy:
    service = ""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.attempts: Counter[str] = Counter()
        self.granted: set[str] = set()

    def auth(self, e: Event) -> Optional[str]:
        self.attempts[e.src_ip] += 1
        note = None
        if e.auth_success is None:
            n = self.settings.fake_accept_after
            if n and self.attempts[e.src_ip] >= n and e.src_ip not in self.granted:
                e.auth_success = True
                self.granted.add(e.src_ip)
                note = f"{self.service} decoy granted a fake login after {self.attempts[e.src_ip]} attempts"
            else:
                e.auth_success = False
        if e.response_code is None:
            e.response_code = 200 if e.auth_success else 401
        return note

    def respond(self, e: Event) -> Optional[str]:
        if e.auth_attempt:
            return self.auth(e)
        if e.tcp_flags == "S" or e.event_type == "probe":
            return f"{self.service or 'tcp'} decoy answered SYN-ACK"
        return None


class HttpDecoy(Decoy):
    service = "http"
    SITE = {"/", "/index.html", "/login", "/about", "/products", "/contact", "/favicon.ico", "/robots.txt"}

    def respond(self, e: Event) -> Optional[str]:
        if e.auth_attempt:
            return self.auth(e)
        if e.http_path is not None and e.response_code is None:
            path = e.http_path.split("?")[0]
            e.response_code = 200 if path in self.SITE else (403 if is_sensitive_path(e.http_path) else 404)
            if is_sensitive_path(e.http_path):
                return "fake site: sensitive path probe logged"
        return super().respond(e)


class ShellDecoy(Decoy):
    """SSH/Telnet (Cowrie-like)."""
    service = "ssh"

    def respond(self, e: Event) -> Optional[str]:
        if e.event_type == "command":
            return "decoy shell: command recorded, nothing executed"
        if e.event_type == "download":
            return "decoy shell: download URL recorded, nothing fetched"
        return super().respond(e)


class FtpDecoy(Decoy):
    service = "ftp"


class MysqlDecoy(Decoy):
    service = "mysql"


class DecoyServices:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.reset()

    def reset(self) -> None:
        ssh = ShellDecoy(self.settings)
        self.decoys = {"http": HttpDecoy(self.settings), "ssh": ssh, "telnet": ssh, "ftp": FtpDecoy(self.settings),
                       "mysql": MysqlDecoy(self.settings)}
        self.generic = Decoy(self.settings)

    def respond(self, e: Event) -> None:
        note = self.decoys.get(e.dst_service, self.generic).respond(e)
        if note:
            e.honeypot_note = note

    def stats(self) -> dict:
        return {k: {"auth_attempts": sum(d.attempts.values()), "fake_logins": len(d.granted)}
                for k, d in self.decoys.items() if k != "telnet"}
