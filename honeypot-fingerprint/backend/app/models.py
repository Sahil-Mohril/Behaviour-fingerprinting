"""Database models (SQLite via SQLModel)."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class EventRow(SQLModel, table=True):
    __tablename__ = "events"
    id: Optional[int] = Field(default=None, primary_key=True)
    seq: int = Field(index=True)
    ts: float = Field(index=True)
    src_ip: str = Field(index=True)
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_service: str = Field(default="other", index=True)
    dst_port: Optional[int] = None
    protocol: str = "TCP"
    tcp_flags: Optional[str] = None
    packet_size: Optional[float] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None
    duration: Optional[float] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    payload_snippet: Optional[str] = None
    response_code: Optional[int] = None
    session_id: Optional[str] = None
    event_type: str = "flow"
    source: str = ""
    ground_truth_label: str = Field(default="", index=True)
    campaign_id: str = ""
    country: str = ""
    asn: str = ""
    action: str = Field(default="accepted", index=True)
    rule_id: Optional[str] = None
    honeypot_note: Optional[str] = None


class EntityRow(SQLModel, table=True):
    """Fingerprints, alerts and rules, stored as JSON documents keyed by (kind, id)."""
    __tablename__ = "entities"
    kind: str = Field(primary_key=True)
    id: str = Field(primary_key=True)
    data: dict = Field(default_factory=dict, sa_column=Column(JSON))


class SettingRow(SQLModel, table=True):
    __tablename__ = "settings"
    key: str = Field(primary_key=True)
    value: dict = Field(default_factory=dict, sa_column=Column(JSON))


class AllowRow(SQLModel, table=True):
    __tablename__ = "allowlist"
    cidr: str = Field(primary_key=True)
    note: str = ""
