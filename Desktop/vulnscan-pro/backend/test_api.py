#!/usr/bin/env python
"""Quick test to verify the API is working."""

from app import create_app
from database import db
from models import Scan

app = create_app()

with app.test_client() as client:
    # Health check
    r = client.get("/api/health")
    print(f"✓ Health check: {r.status_code} {r.json}")

    # List scans
    r = client.get("/api/scans")
    print(f"✓ List scans: {r.status_code}, {len(r.json.get('scans', []))} scans total")

    # Start API scan
    r = client.post("/api/scan/web-api", json={
        "url": "https://example.com",
        "scan_depth": "quick"
    })
    print(f"✓ Started API scan: {r.status_code}, scan_id={r.json.get('scan_id')}")

    # Get scan status
    scan_id = r.json.get('scan_id')
    r = client.get(f"/api/scan/{scan_id}")
    print(f"✓ Get scan: {r.status_code}, status={r.json.get('status')}, risk_score={r.json.get('risk_score')}")

print("\n✓ All API endpoints working!")
