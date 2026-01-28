# Tiger Team Reviewer Playbook
## Independent Validation Guide

**Purpose:** Guide for independent review of security findings before submission

---

## Reviewer Responsibilities

1. Verify evidence chain is complete
2. Validate reproduction steps independently
3. Challenge hypotheses with alternatives
4. Verify fix logic addresses root cause
5. Confirm documentation is complete

---

## Review Checklist

### 1. Evidence Review

| Check | Status | Notes |
|-------|--------|-------|
| HTTP request/response captured | [ ] | |
| Screenshots provided | [ ] | |
| Timestamps documented | [ ] | |
| Environment specified | [ ] | |
| Affected endpoints listed | [ ] | |

**Questions to Ask:**
- Is the evidence sufficient to prove the vulnerability?
- Could this evidence be fabricated?
- Are there gaps in the evidence chain?

### 2. Reproduction Validation

| Check | Status | Notes |
|-------|--------|-------|
| Steps are clear and numbered | [ ] | |
| Prerequisites documented | [ ] | |
| Reproduction is deterministic | [ ] | |
| Works in clean environment | [ ] | |
| Minimal steps to trigger | [ ] | |

**Validation Process:**
```
1. Set up clean environment
2. Follow documented steps exactly
3. Verify same result occurs
4. Attempt slight variations
5. Document any differences
```

### 3. Hypothesis Challenge

| Check | Status | Notes |
|-------|--------|-------|
| ≥3 hypotheses considered | [ ] | |
| Alternatives ruled out | [ ] | |
| Root cause identified | [ ] | |
| Not a symptom of deeper issue | [ ] | |

**Alternative Explanations to Consider:**
- Configuration issue vs code bug
- Client-side vs server-side
- Authentication vs authorization
- Race condition vs logic flaw
- Intended behavior vs vulnerability

### 4. Impact Assessment

| Check | Status | Notes |
|-------|--------|-------|
| Impact accurately described | [ ] | |
| CVSS score reasonable | [ ] | |
| Attack complexity realistic | [ ] | |
| Privileges required correct | [ ] | |
| Scope properly assessed | [ ] | |

**Impact Validation:**
- Can impact be demonstrated without harm?
- Is the worst-case scenario realistic?
- What are the preconditions for exploitation?

### 5. Remediation Review

| Check | Status | Notes |
|-------|--------|-------|
| Fix addresses root cause | [ ] | |
| Fix doesn't mask deeper issue | [ ] | |
| Fix is minimal and scoped | [ ] | |
| No new vulnerabilities introduced | [ ] | |

---

## Severity Validation Matrix

| Claimed | Verify | Criteria |
|---------|--------|----------|
| Critical | Account takeover? RCE? | Full system compromise |
| High | Data breach? Priv esc? | Significant data access |
| Medium | Limited impact? | Requires user interaction |
| Low | Info disclosure? | Minimal security impact |
| Info | Best practice? | No direct security impact |

---

## Common Review Failures

### 1. Insufficient Evidence
**Problem:** PoC doesn't clearly show impact
**Resolution:** Request additional evidence or demo

### 2. Non-Reproducible
**Problem:** Steps don't produce same result
**Resolution:** Clarify environment, timing, or preconditions

### 3. Overstated Impact
**Problem:** Claimed severity exceeds actual impact
**Resolution:** Adjust severity with justification

### 4. Missing Context
**Problem:** Finding lacks business context
**Resolution:** Add attack scenario and real-world impact

### 5. Duplicate/Known Issue
**Problem:** Already reported or known behavior
**Resolution:** Check existing reports, clarify novelty

---

## Review Decision Tree

```
START: New finding received
    │
    ├─ Evidence complete? ──No──→ Request more evidence
    │       │
    │      Yes
    │       │
    ├─ Reproducible? ──No──→ Request clarification
    │       │
    │      Yes
    │       │
    ├─ Root cause identified? ──No──→ Further investigation
    │       │
    │      Yes
    │       │
    ├─ Impact accurate? ──No──→ Adjust severity
    │       │
    │      Yes
    │       │
    ├─ Documentation complete? ──No──→ Request updates
    │       │
    │      Yes
    │       │
    └─ APPROVED FOR SUBMISSION
```

---

## Review Template

```markdown
## Independent Review

**Reviewer:** [Name]
**Date:** [Date]
**Finding:** [Title]

### Evidence Assessment
- [ ] Complete and verifiable
- Quality: [High/Medium/Low]
- Gaps: [None/List gaps]

### Reproduction
- [ ] Successfully reproduced
- Environment: [Details]
- Deviations: [None/List]

### Hypothesis Validation
- [ ] Root cause confirmed
- Alternatives considered: [List]
- Confidence: [High/Medium/Low]

### Impact Validation
- [ ] Severity appropriate
- Adjusted severity: [Same/Changed to X]
- Justification: [If changed]

### Documentation
- [ ] Complete and accurate
- Missing elements: [None/List]

### Decision
- [ ] APPROVED
- [ ] NEEDS REVISION
- [ ] REJECTED

### Comments
[Additional notes]
```

---

## Escalation Criteria

**Escalate to senior reviewer if:**
- Critical severity claimed
- Novel attack vector
- Affects authentication/authorization core
- Potential for mass exploitation
- Legal/compliance implications
- Disagreement with researcher

---

*Tiger Team Reviewer Playbook*
*Independent validation ensures quality*
