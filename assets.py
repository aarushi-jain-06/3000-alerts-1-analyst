"""
Asset inventory with business-criticality weighting.
In a real deployment this table is pulled from a CMDB / asset-management
system (ServiceNow, Lansweeper, etc.) and cached locally.
"""

# Criticality tiers -> numeric weight used in risk scoring.
CRITICALITY_WEIGHT = {
    "CRITICAL": 10,   # domain controllers, core databases, payment systems
    "HIGH": 7,        # internet-facing servers, exec workstations
    "MEDIUM": 4,       # general employee endpoints, internal apps
    "LOW": 1,          # printers, kiosks, non-prod/test boxes
}

ASSET_REGISTRY = {
    "DC01":            {"type": "Domain Controller",      "criticality": "CRITICAL"},
    "DC02":            {"type": "Domain Controller",      "criticality": "CRITICAL"},
    "SQL-FINANCE01":   {"type": "Finance DB Server",       "criticality": "CRITICAL"},
    "PAYGW-PROD":      {"type": "Payment Gateway",         "criticality": "CRITICAL"},
    "WEB03-DMZ":       {"type": "Public Web Server",       "criticality": "HIGH"},
    "VPN-GW01":        {"type": "VPN Gateway",             "criticality": "HIGH"},
    "CEO-LAPTOP":      {"type": "Executive Workstation",   "criticality": "HIGH"},
    "CFO-LAPTOP":      {"type": "Executive Workstation",   "criticality": "HIGH"},
    "HR-APP01":        {"type": "HR Application Server",   "criticality": "MEDIUM"},
    "DEV-BUILD01":     {"type": "CI/CD Build Server",      "criticality": "MEDIUM"},
    "ENG-LAPTOP-114":  {"type": "Employee Workstation",     "criticality": "MEDIUM"},
    "ENG-LAPTOP-233":  {"type": "Employee Workstation",     "criticality": "MEDIUM"},
    "SALES-LAPTOP-08": {"type": "Employee Workstation",     "criticality": "MEDIUM"},
    "MKT-LAPTOP-19":   {"type": "Employee Workstation",     "criticality": "MEDIUM"},
    "FILE-SRV02":      {"type": "File Server",             "criticality": "MEDIUM"},
    "PRINT-SRV01":     {"type": "Print Server",             "criticality": "LOW"},
    "KIOSK-LOBBY":     {"type": "Lobby Kiosk",              "criticality": "LOW"},
    "TEST-VM07":       {"type": "Non-Prod Test VM",         "criticality": "LOW"},
}


def criticality_weight(asset_id: str) -> int:
    info = ASSET_REGISTRY.get(asset_id)
    if not info:
        return CRITICALITY_WEIGHT["MEDIUM"]  # unknown asset -> assume medium
    return CRITICALITY_WEIGHT[info["criticality"]]


def asset_info(asset_id: str) -> dict:
    return ASSET_REGISTRY.get(
        asset_id, {"type": "Unknown Asset", "criticality": "MEDIUM"}
    )
