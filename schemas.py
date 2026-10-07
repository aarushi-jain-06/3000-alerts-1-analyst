"""
schemas.py - Data contract for '3,000 Alerts, One Analyst'.
Defines standard Alert and Incident schemas.
"""

from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, field_validator


class Alert(BaseModel):
    """
    Normalized security alert ingested into the pipeline.
    
    Fields:
        alert_id: Unique string identifier for the alert (e.g. 'ALT-1001').
        timestamp: ISO 8601 formatted timestamp string (e.g. '2026-10-07T08:15:00Z').
        alert_type: Standardized category or detection type (e.g. 'brute_force', 'phishing').
        severity: Alert severity level on a 1-5 scale (1: Low, 5: Critical).
        host: Hostname, asset FQDN, or device identifier (e.g. 'WKSTN-892', 'DC-01').
        user: Account or username involved (e.g. 'jsmith', 'SYSTEM', 'unknown').
        src_ip: Source IP address (e.g. '198.51.100.24' or internal IP).
        dst_ip: Destination IP address (e.g. '10.0.1.15').
        description: Plain-text explanation of the alert trigger and telemetry.
        asset_criticality: Asset importance rating on a 1-5 scale (1: Low / Sandbox, 5: Crown Jewel / DC).
    """
    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(..., description="Timestamp in ISO 8601 format")
    alert_type: str = Field(..., description="Standardized category of the alert")
    severity: int = Field(..., ge=1, le=5, description="Alert severity from 1 to 5")
    host: str = Field(..., description="Hostname or device identifier")
    user: str = Field(default="unknown", description="Username or security principal")
    src_ip: str = Field(default="", description="Source IP address")
    dst_ip: str = Field(default="", description="Destination IP address")
    description: str = Field(..., description="Alert description or telemetry summary")
    asset_criticality: int = Field(..., ge=1, le=5, description="Asset criticality rating from 1 to 5")

    @field_validator("severity", "asset_criticality", mode="before")
    @classmethod
    def validate_range(cls, v: Any) -> int:
        val = int(v)
        if not (1 <= val <= 5):
            raise ValueError(f"Value must be between 1 and 5, got {v}")
        return val

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class Incident(BaseModel):
    """
    Correlated group of alerts representing a potential security incident.
    
    Fields:
        incident_id: Unique identifier for the incident (e.g. 'INC-2026-001').
        alerts: List of Alert objects belonging to this incident cluster.
    """
    incident_id: str = Field(..., description="Unique incident identifier")
    alerts: List[Alert] = Field(..., min_length=1, description="List of grouped alerts")

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def hosts(self) -> List[str]:
        return sorted(list({a.host for a in self.alerts if a.host}))

    @property
    def users(self) -> List[str]:
        return sorted(list({a.user for a in self.alerts if a.user and a.user != "unknown"}))

    @property
    def max_severity(self) -> int:
        return max((a.severity for a in self.alerts), default=1)

    @property
    def max_criticality(self) -> int:
        return max((a.asset_criticality for a in self.alerts), default=1)

    @property
    def start_time(self) -> str:
        return min((a.timestamp for a in self.alerts), default="")

    @property
    def end_time(self) -> str:
        return max((a.timestamp for a in self.alerts), default="")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Incident":
        alerts_data = data.get("alerts", [])
        alerts = [a if isinstance(a, Alert) else Alert(**a) for a in alerts_data]
        return cls(incident_id=data["incident_id"], alerts=alerts)
