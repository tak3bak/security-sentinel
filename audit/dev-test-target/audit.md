# Security Posture Scorecard: dev-test-target
**Date:** 2026-06-30 20:18
---

## Executive Summary
| Metric | Status |
| :--- | :--- |
| **Security Risk Score** | 98/100 |
| **Critical Leaks Detected** | 0 |
| **Brute Force Attempts** | 1 |

## 1. Network Footprint (Listening Services)
- `tcp   LISTEN 0      511         127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=218,fd=8))`
- `tcp   LISTEN 0      4096        127.0.0.1:11434      0.0.0.0:*    users:(("ollama",pid=171,fd=3))      `
- `tcp   LISTEN 0      1000   10.255.255.254:53         0.0.0.0:*                                         `
- `tcp   LISTEN 0      4096                *:3000             *:*                                         `
- `tcp   LISTEN 0      511             [::1]:6379          [::]:*    users:(("redis-server",pid=218,fd=9))`
- `tcp   LISTEN 0      4096                *:5001             *:*                                         `
- `tcp   LISTEN 0      4096                *:9200             *:*                                         `
- `tcp   LISTEN 0      4096                *:1515             *:*                                         `
- `tcp   LISTEN 0      4096                *:55000            *:*                                         `

## 2. Identified Risks
*No leaks or credential exposures detected.*

## 3. Detailed Remediation Steps
*No active remediation steps required.*

### ⚠️ Security Alert
Failed login attempts detected. Active mitigation rules applied to local firewall structures.
