# BlackBox Data Standards

**Inspired by NASA PDS4 and Earth Data Standards**
**Version: 1.0.0**

---

## 1. Core Principles

Following NASA's approach to scientific data management:

### 1.1 Self-Describing Data
All data products include embedded metadata describing structure, provenance, and context.

### 1.2 Platform Independence
Data formats accessible across different computing environments.

### 1.3 Hierarchical Organization
```
Mission (Bundle)
├── Assessment (Collection)
│   ├── Findings (Products)
│   ├── Evidence (Products)
│   └── Reports (Products)
└── Context (Collection)
    ├── Target Profile
    ├── Tool Configurations
    └── Reference Data
```

### 1.4 Unique Identification
Every artifact has a Logical Identifier (LID) following the pattern:
```
urn:blackbox:{mission}:{collection}:{product}::{version}
```

### 1.5 Processing Levels
| Level | Name | Description |
|-------|------|-------------|
| L0 | Raw | Unprocessed tool output |
| L1 | Validated | Verified and deduplicated |
| L2 | Enriched | Correlated with context |
| L3 | Analyzed | Expert-reviewed findings |
| L4 | Actionable | Remediation-ready reports |

---

## 2. Data Dictionary

### 2.1 Core Classes

#### Mission
Top-level container for all related security assessment work.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| lid | string | Yes | Logical identifier |
| name | string | Yes | Human-readable name |
| type | enum | Yes | pentest, bugbounty, audit, research |
| target | Target | Yes | Primary assessment target |
| start_time | datetime | Yes | Mission start timestamp |
| end_time | datetime | No | Mission completion timestamp |
| status | enum | Yes | planning, active, paused, completed |
| scope | Scope | Yes | Authorized boundaries |

#### Assessment
A collection of related security testing activities.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| lid | string | Yes | Logical identifier |
| mission_lid | string | Yes | Parent mission reference |
| name | string | Yes | Assessment name |
| type | enum | Yes | recon, scanning, exploitation, reporting |
| tools | Tool[] | Yes | Tools used |
| findings | Finding[] | No | Discovered issues |
| processing_level | enum | Yes | L0-L4 |

#### Finding
A discovered security issue or observation.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| lid | string | Yes | Logical identifier |
| assessment_lid | string | Yes | Parent assessment |
| title | string | Yes | Brief description |
| severity | enum | Yes | critical, high, medium, low, info |
| cvss | float | No | CVSS score (0-10) |
| cwe | string | No | CWE identifier |
| evidence | Evidence[] | Yes | Supporting proof |
| status | enum | Yes | new, confirmed, false_positive, remediated |
| discovered_at | datetime | Yes | Discovery timestamp |

#### Evidence
Proof supporting a finding.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| lid | string | Yes | Logical identifier |
| finding_lid | string | Yes | Parent finding |
| type | enum | Yes | screenshot, log, request, response, code |
| content | binary/text | Yes | Actual evidence data |
| hash | string | Yes | SHA-256 integrity hash |
| captured_at | datetime | Yes | Capture timestamp |

#### Target
The subject of security assessment.

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| lid | string | Yes | Logical identifier |
| name | string | Yes | Target name |
| type | enum | Yes | web, api, mobile, network, cloud, iot |
| identifiers | Identifier[] | Yes | URLs, IPs, domains |
| technologies | string[] | No | Detected tech stack |
| scope_constraints | Scope | Yes | What's in/out of scope |

---

## 3. Label Schema

Every product requires a label file (YAML format) with standardized sections:

### 3.1 Label Structure

```yaml
# Product Label Schema
identification_area:
  lid: "urn:blackbox:mission-001:recon:nmap-scan-001::1.0"
  version: "1.0"
  title: "Nmap Port Scan Results"
  product_class: "Finding"

observation_area:
  mission_lid: "urn:blackbox:mission-001"
  assessment_lid: "urn:blackbox:mission-001:recon"
  target_lid: "urn:blackbox:target:example-com"
  start_time: "2026-01-27T10:00:00Z"
  end_time: "2026-01-27T10:15:00Z"
  processing_level: "L1"

context_area:
  tools:
    - name: "nmap"
      version: "7.94"
      parameters: "-sV -sC -p-"
  environment:
    platform: "linux"
    network: "external"

file_area:
  file:
    name: "nmap-scan-001.xml"
    size: 45678
    checksum:
      type: "SHA-256"
      value: "abc123..."
    format: "XML"

reference_list:
  internal_references:
    - lid: "urn:blackbox:mission-001:recon"
      type: "parent"
    - lid: "urn:blackbox:finding:open-ports-001"
      type: "derived"

provenance:
  created_by: "blackbox-scanner"
  created_at: "2026-01-27T10:15:00Z"
  modified_at: "2026-01-27T10:15:00Z"
  audit_trail:
    - action: "created"
      timestamp: "2026-01-27T10:15:00Z"
      actor: "automated"
```

---

## 4. Directory Structure

```
blackbox/
├── missions/                    # Bundle level
│   └── {mission-id}/
│       ├── mission.label.yaml   # Mission metadata
│       ├── scope.yaml           # Authorized scope
│       ├── assessments/         # Collection level
│       │   └── {assessment-id}/
│       │       ├── assessment.label.yaml
│       │       ├── products/    # Product level
│       │       │   ├── {product-id}.label.yaml
│       │       │   └── {product-id}.data
│       │       └── evidence/
│       │           └── {evidence-id}/
│       ├── findings/
│       │   └── {finding-id}/
│       │       ├── finding.label.yaml
│       │       └── evidence/
│       ├── reports/
│       │   ├── executive.label.yaml
│       │   ├── executive.pdf
│       │   ├── technical.label.yaml
│       │   └── technical.md
│       └── context/
│           ├── target.label.yaml
│           └── tools.label.yaml
│
├── context/                     # Global context products
│   ├── tools/                   # Tool reference data
│   │   └── {tool-id}.label.yaml
│   ├── cwe/                     # CWE reference
│   └── cvss/                    # CVSS calculator data
│
├── dictionaries/                # Data dictionaries
│   ├── core.yaml                # Core class definitions
│   ├── security.yaml            # Security-specific terms
│   └── tools.yaml               # Tool definitions
│
└── schemas/                     # Validation schemas
    ├── mission.schema.yaml
    ├── assessment.schema.yaml
    ├── finding.schema.yaml
    └── label.schema.yaml
```

---

## 5. Workflow States

Inspired by NASA's lifecycle milestone tracking:

### 5.1 Mission Lifecycle
```
PLANNING → SCOPING → ACTIVE → ANALYSIS → REPORTING → CLOSED
    ↓         ↓         ↓         ↓          ↓
   SRR       PDR       CDR     Review    Delivery
```

### 5.2 Finding Lifecycle
```
DISCOVERED → VALIDATED → ENRICHED → CONFIRMED → REPORTED → TRACKED
     L0          L1          L2         L3          L4       Archive
```

### 5.3 Evidence Chain
```
CAPTURED → HASHED → LABELED → LINKED → ARCHIVED
```

---

## 6. Naming Conventions

### 6.1 Logical Identifiers (LID)
```
urn:blackbox:{namespace}:{type}:{identifier}::{version}

Examples:
urn:blackbox:mission:pentest-acme-2026::1.0
urn:blackbox:mission:pentest-acme-2026:recon:nmap-001::1.0
urn:blackbox:finding:sqli-login-001::1.0
urn:blackbox:evidence:screenshot-001::1.0
```

### 6.2 File Naming
```
{type}_{identifier}_{timestamp}.{ext}

Examples:
scan_nmap_20260127T100000Z.xml
finding_sqli_20260127T103000Z.yaml
evidence_screenshot_20260127T103500Z.png
report_executive_20260127T120000Z.pdf
```

### 6.3 Directory Naming
- Use lowercase with hyphens
- Include type prefix where applicable
- Dates in ISO 8601 format

---

## 7. Validation Requirements

### 7.1 Label Validation
- All products must have valid labels
- Labels must pass schema validation
- LIDs must be unique within namespace
- References must resolve to existing products

### 7.2 Data Validation
- Checksums verified on read/write
- Format compliance checked
- Required fields present
- Enum values from allowed set

### 7.3 Provenance Validation
- Audit trail complete
- Timestamps sequential
- Actor identification present

---

## 8. Integration with Existing Systems

These standards enhance but don't replace existing BlackBox functionality:

| Existing | Enhanced With |
|----------|---------------|
| `/reports/` | Labels, versioning, LIDs |
| `/targets/` | Target profiles with context |
| `/config/` | Tool reference dictionaries |
| `/workflows/` | Lifecycle state tracking |
| `/modules/` | Processing level metadata |

---

## References

- NASA PDS4 Standards: https://pds.nasa.gov/datastandards/
- NASA Earth Data Formats: https://earthdata.nasa.gov/learn/earth-observation-data-basics
- CADRE Database Methodology: https://nasa.gov/ocfo/ppc-corner/cadre/
