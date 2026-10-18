"""Behaviour vocabulary and the single dataset-label -> behaviour mapping table.

Ground-truth labels are stored exactly as they appear in the dataset. The evaluation
layer maps them through `LABEL_MAP`. The detection pipeline never reads them.
"""
from __future__ import annotations

import re

# key: (display name, default severity, benign?)
BEHAVIOURS: dict[str, tuple[str, str, bool]] = {
    "benign": ("Normal / benign traffic", "info", True),
    "crawler": ("Search-engine crawler", "info", True),
    "scraper": ("Aggressive scraper", "low", False),
    "http_flood": ("HTTP flood (L7 DoS/DDoS)", "high", False),
    "syn_flood": ("SYN flood", "high", False),
    "udp_flood": ("UDP flood / amplification", "high", False),
    "icmp_flood": ("ICMP flood", "medium", False),
    "slowloris": ("Slowloris / low-and-slow", "medium", False),
    "port_scan_fast": ("Port scan (fast)", "medium", False),
    "port_scan_slow": ("Port scan (stealthy)", "low", False),
    "ssh_bruteforce": ("SSH brute force", "high", False),
    "ftp_bruteforce": ("FTP brute force", "high", False),
    "web_bruteforce": ("Web login brute force", "high", False),
    "credential_stuffing": ("Credential stuffing", "high", False),
    "post_login_shell": ("Post-login shell activity", "critical", False),
    "web_vuln_probe": ("Web vuln probing", "medium", False),
    "botnet_c2": ("Botnet / C2 beaconing", "high", False),
    "infiltration": ("Infiltration / exploit", "critical", False),
    "malware_download": ("Malware download", "critical", False),
}
UNKNOWN = "unknown_anomaly"
UNMATCHED = "unmatched"
CATEGORY_NAMES = {k: v[0] for k, v in BEHAVIOURS.items()} | {UNKNOWN: "Unknown anomaly", UNMATCHED: "Unclassified"}
SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_of(category: str) -> str:
    if category in BEHAVIOURS:
        return BEHAVIOURS[category][1]
    return "medium" if category == UNKNOWN else "info"


def is_benign(category: str) -> bool:
    return category in BEHAVIOURS and BEHAVIOURS[category][2]


def severity_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


# Raw dataset label (normalised: lowercase, non-alphanumerics collapsed to "_") -> behaviour.
LABEL_MAP: dict[str, str] = {
    # CIC-IDS2017
    "benign": "benign",
    "dos_hulk": "http_flood",
    "dos_goldeneye": "http_flood",
    "ddos": "http_flood",  # 2017 DDoS = LOIC HTTP flood
    "dos_slowloris": "slowloris",
    "dos_slowhttptest": "slowloris",
    "portscan": "port_scan_fast",
    "ssh_patator": "ssh_bruteforce",
    "ftp_patator": "ftp_bruteforce",
    "bot": "botnet_c2",
    "web_attack_brute_force": "web_bruteforce",
    "web_attack_xss": "web_vuln_probe",
    "web_attack_sql_injection": "web_vuln_probe",
    "infiltration": "infiltration",
    "heartbleed": "infiltration",
    # CIC-DDoS2019
    "syn": "syn_flood",
    "drdos_dns": "udp_flood", "drdos_ldap": "udp_flood", "drdos_mssql": "udp_flood",
    "drdos_netbios": "udp_flood", "drdos_ntp": "udp_flood", "drdos_snmp": "udp_flood",
    "drdos_ssdp": "udp_flood", "drdos_udp": "udp_flood", "udp": "udp_flood", "udp_lag": "udp_flood",
    "udplag": "udp_flood", "tftp": "udp_flood", "ldap": "udp_flood", "mssql": "udp_flood",
    "netbios": "udp_flood", "portmap": "udp_flood",
    "webddos": "http_flood",
    # Zeek conn.log.labeled (IoT-23 style detailed-label)
    "partofahorizontalportscan": "port_scan_fast",
    "c_c": "botnet_c2", "c_c_heartbeat": "botnet_c2", "c_c_filedownload": "malware_download",
    "c_c_torii": "botnet_c2", "c_c_mirai": "botnet_c2", "c_c_heartbeat_filedownload": "malware_download",
    "heartbeat": "botnet_c2", "okiru": "botnet_c2", "okiru_attack": "botnet_c2",
    "filedownload": "malware_download", "attack": "infiltration",
    "partofahorizontalportscan_attack": "port_scan_fast",
    "malicious": UNKNOWN,
}

# Behaviours that none of the supported labelled datasets provide.
NO_DATA_SOURCE = {
    "crawler": "No labelled source among CIC-IDS2017/CIC-DDoS2019/IoT-23.",
    "scraper": "No labelled source among CIC-IDS2017/CIC-DDoS2019/IoT-23.",
    "icmp_flood": "No labelled source among CIC-IDS2017/CIC-DDoS2019/IoT-23.",
    "port_scan_slow": "No labelled slow-scan class; CIC PortScan is a fast nmap scan.",
    "credential_stuffing": "No labelled source; Cowrie/OpenCanary logs are unlabelled (use a label override).",
    "post_login_shell": "Cowrie command logs carry no label (use a label override when replaying).",
}


def normalise_label(raw: str) -> str:
    s = (raw or "").strip().lower()
    s = s.replace("�", "-").replace("–", "-")
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s


def map_label(raw: str) -> str:
    """Dataset label -> behaviour key ('' if unlabelled, UNKNOWN if unrecognised)."""
    if not raw or raw in ("-", "(empty)"):
        return ""
    if raw in BEHAVIOURS:  # already a behaviour key (label override)
        return raw
    n = normalise_label(raw)
    if n in LABEL_MAP:
        return LABEL_MAP[n]
    for key in ("benign",):
        if n.startswith(key):
            return LABEL_MAP[key]
    return UNKNOWN


def behaviour_table() -> list[dict]:
    sources: dict[str, list[str]] = {}
    for raw, beh in LABEL_MAP.items():
        sources.setdefault(beh, []).append(raw)
    return [
        {
            "key": k, "name": name, "severity": sev, "benign": benign,
            "dataset_labels": sorted(sources.get(k, [])),
            "data_source": "no data source" if k in NO_DATA_SOURCE else "available",
            "note": NO_DATA_SOURCE.get(k, ""),
        }
        for k, (name, sev, benign) in BEHAVIOURS.items()
    ]
