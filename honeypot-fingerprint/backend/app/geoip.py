"""Offline GeoIP mock: deterministic fake country/ASN for simulated IPs."""
from __future__ import annotations

import hashlib
from functools import lru_cache

_TABLE = [
    ("US", "AS64501 ExampleCloud"), ("US", "AS64502 Residential-NA"), ("DE", "AS64510 Hosting-EU"),
    ("NL", "AS64511 VPS-Amsterdam"), ("FR", "AS64512 Fibre-FR"), ("GB", "AS64513 Broadband-UK"),
    ("RU", "AS64520 DataCenter-RU"), ("CN", "AS64530 Telecom-CN"), ("CN", "AS64531 Cloud-CN"),
    ("BR", "AS64540 Mobile-BR"), ("IN", "AS64550 ISP-IN"), ("VN", "AS64551 ISP-VN"),
    ("KR", "AS64552 Broadband-KR"), ("SG", "AS64553 Cloud-SG"), ("UA", "AS64521 Hosting-UA"),
    ("IR", "AS64560 ISP-IR"), ("ID", "AS64554 ISP-ID"), ("JP", "AS64555 Fibre-JP"),
    ("CA", "AS64503 Cable-CA"), ("RO", "AS64514 Bulletproof-RO"), ("TR", "AS64515 ISP-TR"),
    ("ZA", "AS64570 ISP-ZA"), ("AR", "AS64541 ISP-AR"), ("PL", "AS64516 Hosting-PL"),
]


@lru_cache(maxsize=200_000)
def lookup(ip: str) -> tuple[str, str]:
    """Map an IP to (country, asn). Keyed on the /16 so neighbours share an ASN."""
    prefix = ".".join(ip.split(".")[:2])
    h = int(hashlib.blake2b(prefix.encode(), digest_size=4).hexdigest(), 16)
    return _TABLE[h % len(_TABLE)]
