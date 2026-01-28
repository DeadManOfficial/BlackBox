# BlackBox AI - API Reference

## Overview

BlackBox AI provides both REST API and MCP (Model Context Protocol) interfaces for security automation.

**Base URL**: `http://localhost:8888`

---

## Authentication

Currently, BlackBox runs locally without authentication. For production deployments, implement token-based auth.

---

## Core Endpoints

### Health Check

```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "modules_loaded": 11,
  "tools_available": 150
}
```

### System Info

```http
GET /api/info
```

**Response**:
```json
{
  "name": "BlackBox AI",
  "version": "1.0.0",
  "modules": ["core_scanning", "reconnaissance", "web_attacks", ...],
  "uptime": 3600
}
```

---

## Module Endpoints

### List Modules

```http
GET /api/modules
```

**Response**:
```json
{
  "modules": [
    {
      "name": "core_scanning",
      "version": "1.0.0",
      "category": "scanning",
      "enabled": true,
      "tools": ["nmap", "nuclei", "gobuster"]
    }
  ]
}
```

### Get Module Info

```http
GET /api/modules/{module_name}
```

**Response**:
```json
{
  "name": "core_scanning",
  "version": "1.0.0",
  "description": "Core vulnerability scanning tools",
  "tools": ["nmap", "nuclei", "gobuster"],
  "routes": ["/api/scan/nmap", "/api/scan/nuclei"]
}
```

---

## Scanning Endpoints

### Nmap Scan

```http
POST /api/scan/nmap
```

**Request Body**:
```json
{
  "target": "192.168.1.1",
  "ports": "1-1000",
  "args": "-sV -sC",
  "timeout": 300
}
```

**Response**:
```json
{
  "success": true,
  "scan_id": "scan_abc123",
  "results": {
    "ports": [
      {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 8.9"},
      {"port": 80, "state": "open", "service": "http", "version": "nginx 1.18"}
    ],
    "host_status": "up"
  }
}
```

### Nuclei Scan

```http
POST /api/scan/nuclei
```

**Request Body**:
```json
{
  "target": "https://example.com",
  "severity": "high,critical",
  "tags": "cve,xss",
  "timeout": 600
}
```

**Response**:
```json
{
  "success": true,
  "findings": [
    {
      "template_id": "CVE-2021-44228",
      "severity": "critical",
      "host": "https://example.com",
      "matched_at": "/api/endpoint"
    }
  ],
  "stats": {
    "total": 1,
    "critical": 1,
    "high": 0
  }
}
```

### Gobuster Directory Scan

```http
POST /api/scan/gobuster
```

**Request Body**:
```json
{
  "target": "https://example.com",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "extensions": "php,html,js",
  "threads": 50
}
```

---

## Reconnaissance Endpoints

### Subdomain Enumeration

```http
POST /api/recon/subdomains
```

**Request Body**:
```json
{
  "domain": "example.com",
  "tools": ["subfinder", "amass"],
  "passive_only": true
}
```

### Technology Detection

```http
POST /api/recon/tech
```

**Request Body**:
```json
{
  "target": "https://example.com"
}
```

**Response**:
```json
{
  "technologies": [
    {"name": "nginx", "version": "1.18", "category": "web-server"},
    {"name": "React", "version": "18.x", "category": "javascript-framework"}
  ]
}
```

---

## Pentest Endpoints

### Start Assessment

```http
POST /api/pentest/start
```

**Request Body**:
```json
{
  "target": "example.com",
  "scope": ["*.example.com"],
  "engagement_type": "full"
}
```

### Get Status

```http
GET /api/pentest/status
```

**Response**:
```json
{
  "assessment_id": "pentest_xyz",
  "phase": "P2",
  "access_level": "none",
  "findings_count": 5,
  "started_at": "2026-01-26T10:00:00Z"
}
```

### Add Finding

```http
POST /api/pentest/finding
```

**Request Body**:
```json
{
  "phase": "P2",
  "severity": "high",
  "title": "SQL Injection in Login",
  "description": "The login form is vulnerable to SQL injection",
  "tool": "sqlmap",
  "evidence": "POST /login HTTP/1.1\n...",
  "remediation": "Use parameterized queries"
}
```

### Get Report

```http
GET /api/pentest/report
```

**Response**:
```json
{
  "phase": "P2",
  "access_level": "user",
  "findings_summary": {
    "total": 10,
    "critical": 1,
    "high": 3,
    "medium": 4,
    "low": 2
  },
  "findings": [...],
  "recommendations": [...]
}
```

---

## CTF Endpoints

### Decode Data

```http
POST /api/ctf/decode
```

**Request Body**:
```json
{
  "data": "SGVsbG8gV29ybGQh",
  "encoding": "base64"
}
```

**Response**:
```json
{
  "decoded": "Hello World!",
  "encoding_detected": "base64"
}
```

### Hash Data

```http
POST /api/ctf/hash
```

**Request Body**:
```json
{
  "data": "password123"
}
```

**Response**:
```json
{
  "md5": "482c811da5d5b4bc6d497ffa98491e38",
  "sha1": "cbfdac6008f9cab4083784cbd1874f76618d2a97",
  "sha256": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
}
```

### ROT Cipher

```http
POST /api/ctf/rot
```

**Request Body**:
```json
{
  "text": "hello",
  "shift": 13
}
```

---

## Payload Endpoints

### Generate Shellcode

```http
POST /api/payloads/shellcode
```

**Request Body**:
```json
{
  "template": "reverse_shell_bash",
  "lhost": "10.0.0.1",
  "lport": 4444
}
```

### Encode Payload

```http
POST /api/payloads/encode
```

**Request Body**:
```json
{
  "payload": "test_payload",
  "methods": ["base64", "hex"]
}
```

---

## Agent Endpoints

### List Agents

```http
GET /api/agents
```

**Response**:
```json
{
  "agents": [
    {
      "name": "penetration-tester",
      "description": "Expert penetration testing agent",
      "capabilities": ["scanning", "exploitation", "reporting"]
    }
  ]
}
```

### Get Agent Prompt

```http
GET /api/agents/{agent_name}/prompt
```

**Response**:
```json
{
  "name": "penetration-tester",
  "system_prompt": "You are an expert penetration tester..."
}
```

---

## Error Responses

All endpoints return errors in this format:

```json
{
  "success": false,
  "error": {
    "code": "TOOL_NOT_AVAILABLE",
    "message": "nmap is not installed on this system",
    "details": {}
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Missing or invalid parameters |
| `TOOL_NOT_AVAILABLE` | Required tool not installed |
| `TIMEOUT` | Operation exceeded timeout |
| `PERMISSION_DENIED` | Insufficient permissions |
| `MODULE_NOT_FOUND` | Requested module not loaded |

---

## Rate Limiting

Default limits (configurable):
- 100 requests/minute for scanning endpoints
- 1000 requests/minute for info endpoints

---

## WebSocket Events

For real-time updates, connect to:

```
ws://localhost:8888/ws/events
```

### Event Types

```json
{"type": "scan_progress", "scan_id": "...", "progress": 45}
{"type": "finding_discovered", "finding": {...}}
{"type": "phase_complete", "phase": "P1"}
```
