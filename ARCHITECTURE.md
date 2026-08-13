# Nomadik Security Sentinel: System Architecture & MCP Specification

## 1. Overview
Nomadik Security Sentinel is an active-defense, threat-hunting, and compliance investigation platform built with Python 3.12, FastAPI, and containerized microservices.

## 2. Core Subsystems
- **Watcher & Inspector (`src/security_sentinel/watcher.py`, `file_inspector.py`)**: Real-time filesystem listener, Shannon entropy analysis, deterministic secret pattern isolation, and collision-proof quarantine.
- **EDR Threat Detection (`src/security_sentinel/edr_threat_rules.py`)**: CVE-2026-34348 WebAuthn event log auditor, Chrome memory inspection (SDS token extraction defense), and Windows Hello device claim anomalies.
- **Chokepoint Remediation (`src/security_sentinel/chokepoint_finder.py`)**: Algorithmic reduction of finding volumes into single-action remediations with weighted risk scoring and HITL validation.
- **Compliance Investigator (`src/security_sentinel/evidence_investigator.py`)**: Wazuh log correlation, CVE matching, cryptographic SHA-256 evidence hashing, and SOC 2 Type II / ISO 27001 control mapping.
- **Unified API Gateway (`src/security_sentinel/main_app.py`)**: High-performance REST endpoints exposing chokepoints, dispositions, and service health.
