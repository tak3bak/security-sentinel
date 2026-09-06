import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from security_sentinel.chokepoint_finder import (
    router, CHOKEPOINT_STORE, VulnerabilityFinding, SeverityEnum, ResourceTypeEnum, ApprovalStatusEnum
)

app = FastAPI()
app.include_router(router)
client = TestClient(app)

def test_chokepoint_analyze_empty():
    response = client.post("/api/v1/chokepoints/analyze", json={"findings": []})
    assert response.status_code == 400

def test_chokepoint_analyze_and_flow():
    CHOKEPOINT_STORE.clear()
    findings = [
        {
            "id": "f1",
            "cve_id": "CVE-2026-0001",
            "title": "Container Vuln",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_resource": "app-server",
            "resource_type": "container_image",
            "package_name": "base-image",
            "fix_version": "v2.0"
        },
        {
            "id": "f2",
            "cve_id": "CVE-2026-0002",
            "title": "IAM Vuln",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "affected_resource": "aws-role",
            "resource_type": "iam_role",
            "iam_role_name": "AdminRole",
            "suggested_policy": "LeastPrivilege"
        },
        {
            "id": "f3",
            "title": "Package Vuln",
            "severity": "MEDIUM",
            "cvss_score": 5.5,
            "affected_resource": "app-server",
            "package_name": "openssl",
            "fix_version": "1.1.1w"
        },
        {
            "id": "f4",
            "title": "Config Vuln",
            "severity": "LOW",
            "cvss_score": 3.0,
            "affected_resource": "server-01"
        }
    ]
    
    response = client.post("/api/v1/chokepoints/analyze", json={"findings": findings})
    assert response.status_code == 200
    data = response.json()
    assert data["total_raw_findings"] == 4
    assert data["condensed_chokepoints_count"] == 4
    
    # List chokepoints
    res_list = client.get("/api/v1/chokepoints/")
    assert res_list.status_code == 200
    chks = res_list.json()
    assert len(chks) == 4
    
    chk_id = chks[0]["chokepoint_id"]
    
    # Filter by status
    res_filter = client.get("/api/v1/chokepoints/?status=PENDING_APPROVAL")
    assert res_filter.status_code == 200
    assert len(res_filter.json()) == 4
    
    # Approve chokepoint
    res_approve = client.post(
        f"/api/v1/chokepoints/{chk_id}/approve",
        json={
            "approved_by": "Kalen Vandenbos",
            "action": "APPROVED",
            "remediation_notes": "Verified and approved for deployment."
        }
    )
    assert res_approve.status_code == 200
    assert res_approve.json()["status"] == "APPROVED"
    
    # Filter by approved status
    res_filter_approved = client.get("/api/v1/chokepoints/?status=APPROVED")
    assert res_filter_approved.status_code == 200
    assert len(res_filter_approved.json()) == 1

def test_approve_chokepoint_not_found():
    response = client.post(
        "/api/v1/chokepoints/chk_nonexistent/approve",
        json={
            "approved_by": "Kalen Vandenbos",
            "action": "APPROVED"
        }
    )
    assert response.status_code == 404
