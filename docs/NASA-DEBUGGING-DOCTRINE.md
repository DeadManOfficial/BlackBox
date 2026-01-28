# NASA Debugging Doctrine
## Fault Isolation & Investigation Methodology

**Source:** NASA Systems Engineering Handbook, Fault Tree Analysis, Mission Assurance

---

## Core Principles

### 1. Golden State Capture

**Definition:** A complete, frozen snapshot of system state at failure time.

**Required Elements:**
- All inputs (parameters, configurations, user actions)
- All outputs (responses, logs, errors)
- Environment state (versions, dependencies, resources)
- Timestamp with millisecond precision
- System configuration (feature flags, settings)

**Implementation:**
```python
class GoldenState:
    def capture(self):
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "inputs": self.capture_inputs(),
            "outputs": self.capture_outputs(),
            "environment": {
                "versions": self.get_versions(),
                "config": self.get_config(),
                "resources": self.get_resource_state()
            },
            "hash": self.compute_state_hash()
        }
```

**Rule:** IF debugging begins AND Golden State is not captured → STOP

---

### 2. System Boundary Definition

**Definition:** Explicit mapping of system interfaces and dependencies.

**Required Elements:**
- Input interfaces (what enters the system)
- Output interfaces (what leaves the system)
- Internal transforms (what the system does)
- External dependencies (what the system relies on)
- Trust boundaries (where security perimeters exist)

**Template:**
```
┌─────────────────────────────────────────────────┐
│                  SYSTEM BOUNDARY                 │
├─────────────────────────────────────────────────┤
│ INPUTS:                                         │
│   - User requests via REST API                  │
│   - Configuration from environment              │
│   - Secrets from vault                          │
│                                                 │
│ TRANSFORMS:                                     │
│   - Request validation                          │
│   - Business logic processing                   │
│   - Data persistence                            │
│                                                 │
│ OUTPUTS:                                        │
│   - API responses                               │
│   - Database writes                             │
│   - Event emissions                             │
│                                                 │
│ DEPENDENCIES:                                   │
│   - Database (PostgreSQL 15)                    │
│   - Cache (Redis 7)                             │
│   - Auth service (OAuth 2.0)                    │
└─────────────────────────────────────────────────┘
```

**Rule:** IF failure exists AND system boundaries undefined → STOP

---

### 3. Fault Tree Analysis (FTA)

**Definition:** Top-down, deductive failure analysis.

**Structure:**
```
TOP EVENT (Observed Failure)
├── AND Gate: All conditions must be true
│   ├── Condition A
│   └── Condition B
└── OR Gate: Any condition can cause failure
    ├── Possible Cause 1
    ├── Possible Cause 2
    └── Possible Cause 3
```

**Example:**
```
AUTHENTICATION BYPASS
├── [OR] Token Validation Failure
│   ├── Signature not verified
│   ├── Expiration not checked
│   └── Algorithm confusion
├── [OR] Session Hijacking
│   ├── Cookie not HttpOnly
│   ├── XSS vulnerability
│   └── Predictable session ID
└── [OR] Logic Flaw
    ├── Race condition
    ├── TOCTOU vulnerability
    └── Default allow
```

**Rule:** Fault tree must enumerate ALL possible causes before hypothesis formation.

---

### 4. Multiple Hypothesis Generation

**Definition:** Generate at least 3 competing explanations before testing.

**Rationale:** Single hypothesis leads to confirmation bias.

**Template:**
| # | Hypothesis | Evidence For | Evidence Against | Falsification Test |
|---|------------|--------------|------------------|-------------------|
| 1 | [Theory A] | [Supporting data] | [Contradicting data] | [Test to disprove] |
| 2 | [Theory B] | [Supporting data] | [Contradicting data] | [Test to disprove] |
| 3 | [Theory C] | [Supporting data] | [Contradicting data] | [Test to disprove] |

**Rule:** IF only 1 hypothesis exists → Generate more OR STOP

---

### 5. Falsification-Only Testing

**Definition:** Tests must be designed to DISPROVE hypotheses, not confirm them.

**Correct Approach:**
```
Hypothesis: "The bug is caused by null input"
Falsification test: "If I provide non-null input, the bug should NOT occur"
Result: Bug still occurs with non-null input
Conclusion: Hypothesis FALSIFIED - not the cause
```

**Incorrect Approach:**
```
Hypothesis: "The bug is caused by null input"
Confirmation test: "If I provide null input, the bug occurs"
Result: Bug occurs
Conclusion: INVALID - this only shows correlation, not causation
```

**Rule:** IF test confirms without falsifying alternatives → Test is INVALID

---

### 6. Tiger Team Review

**Definition:** Independent review by uninvolved experts before closure.

**Tiger Team Responsibilities:**
1. Verify evidence chain is complete
2. Validate reproduction steps work independently
3. Challenge hypothesis with alternative explanations
4. Verify fix logic addresses root cause
5. Confirm documentation is complete

**Checklist:**
- [ ] Evidence is reproducible by reviewer
- [ ] At least 3 hypotheses were considered
- [ ] Falsification tests documented
- [ ] Fix is minimal and reversible
- [ ] Regression test exists
- [ ] Documentation updated

**Rule:** IF Tiger Team disagrees → Resolve with data OR STOP

---

### 7. Minimal Change Doctrine

**Definition:** Fixes must be the smallest possible change that addresses root cause.

**Correct:**
```diff
- if (user.role == "admin") {
+ if (user.role === "admin" && user.verified) {
    grantAccess();
  }
```

**Incorrect:**
```diff
- if (user.role == "admin") {
-   grantAccess();
- }
+ const verifyAdmin = (user) => {
+   const roles = getRoles(user);
+   const verified = checkVerification(user);
+   const permissions = getPermissions(user);
+   return roles.includes("admin") && verified && permissions.admin;
+ };
+ if (verifyAdmin(user)) {
+   logAccess(user);
+   grantAccess();
+   updateMetrics();
+ }
```

**Rule:** IF fix changes more than necessary → REJECT

---

## NASA Debugging Checklist

### Pre-Investigation
- [ ] Authorization documented
- [ ] Golden State captured
- [ ] System boundaries defined
- [ ] Success criteria established

### Investigation
- [ ] Failure type classified
- [ ] Fault tree constructed
- [ ] ≥3 hypotheses generated
- [ ] Falsification tests designed
- [ ] Layer isolation performed

### Resolution
- [ ] Root cause identified with evidence
- [ ] Fix is minimal and reversible
- [ ] Rollback plan documented
- [ ] Regression test created
- [ ] Tiger Team review complete

### Closure
- [ ] Timeline documented
- [ ] Evidence archived
- [ ] Documentation updated
- [ ] Lessons learned recorded

---

## Integration with Bug Bounty

**Mapping:**
| NASA Concept | Bug Bounty Application |
|--------------|------------------------|
| Golden State | Request/response capture |
| System Boundary | Attack surface mapping |
| Fault Tree | Vulnerability classification |
| Hypothesis | Attack vectors |
| Falsification | PoC validation |
| Tiger Team | Triage team review |
| Minimal Change | Remediation advice |

---

*NASA Debugging Doctrine - Adapted for Security Research*
*Evidence > Opinion | Reproducibility > Speed | System > Symptom*
