"""Shared OCSF-style event contract for all Prahari services."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Actor(BaseModel):
    user: str | None = None
    host: str | None = None


class Endpoint(BaseModel):
    ip: str | None = None
    port: int | None = None


class ProcessInfo(BaseModel):
    name: str | None = None
    pid: int | None = None
    cmdline: str | None = None


class FileInfo(BaseModel):
    path: str | None = None


class SecurityEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    activity: Literal["process", "network", "auth", "file"]
    severity: int = Field(ge=0, le=100)
    actor: Actor = Field(default_factory=Actor)
    src: Endpoint = Field(default_factory=Endpoint)
    dst: Endpoint = Field(default_factory=Endpoint)
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    file: FileInfo = Field(default_factory=FileInfo)
    raw: dict[str, Any] = Field(default_factory=dict)
